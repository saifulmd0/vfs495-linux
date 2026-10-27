#!/usr/bin/env python3
"""EXPERIMENTAL native VFS495 capture: no HP binary, no gdb. Same interface as the gdb-based capture.py.

Status: capture + decryption work; the image assembly (vfs495_assemble.py, modelled on HP's) matches
HP's own images offline (score ~50 vs HP's 78 HP-to-HP) but is not yet validated live. Not used by the bridge.

    sudo python3 vfs495_native_capture.py OUT.pgm        env: VFS_TIMEOUT (s to wait for a finger, default 60)
                                                          VFS495_CAPTURES=DIR with init_cmds.json + capture_cmds.json
                                                          VFS_RAW=FILE.npy also saves the raw scan lines (biometric data!)

Pipeline: secure session (ssl_session.py) -> setup/calibration commands -> arming command with a fresh
random AES-256 image key -> poll 17 until a finger is on -> stream the encrypted swipe from ep 0x82 and
decrypt it on the fly (one AES-256-CBC stream) -> stop when the sensor ends the stream (it does so ~0.4 s
after the finger leaves) or line energy stays low -> descramble (driver/vfs495_descramble.inc) ->
vfs495_assemble.py -> 8-bit PGM (<= 300 x 200, like HP's). The session is always closed (close_notify).

Needs captures/init_cmds.json (runtime/trace_to_init.py) and captures/capture_cmds.json (HP's setup
commands, decrypted once from a traced HP session; HP's data, not redistributed).
Exit codes: 0 ok, 10 no finger / no usable swipe, 1 other error.
"""
import json
import os
import re
import secrets
import signal
import socket
import struct
import sys
import time

import numpy as np
import usb.core
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import vfs495_assemble  # noqa: E402
import ssl_session as S  # noqa: E402

CAP = os.environ.get("VFS495_CAPTURES", HERE + "/../captures")
KEY_OFF, IV_OFF, ARM_LEN = 2927, 2959, 3033   # image key/IV inside the arming command (02, 3033 B)
FRAME, HDR, WIDTH, MAIN = 272, 8, 264, 200    # decrypted frame: 8 B header + 264 pixels; cols 0..199 = print
READ_TIMEOUT_MS = 150      # the sensor ends the stream on its own; a read timeout = swipe over
QUIET_LINES = 300          # backup end rule: this many lines below QUIET_FRAC * peak energy
QUIET_FRAC = 0.1           # low: the swipe's faint tail still carries print (HP uses it)
MAX_SWIPE_S = 4.0
MIN_LINES = 400            # fewer decoded lines than this = no usable swipe


def descramble_table():
    src = open(HERE + "/../driver/vfs495_descramble.inc").read().split("{", 1)[1].split("}", 1)[0]
    perm = [int(x) for x in re.findall(r"\b\d+\b", src)]
    assert sorted(perm) == list(range(WIDTH)), "bad descramble table"
    return np.array(perm)           # out[perm[i]] = raw[i]


def line_energy(px, inv_main):
    """Ridge contrast of one raw line: mean |difference| of neighbouring main-image pixels."""
    v = px[inv_main].astype(np.int16)
    return float(np.abs(np.diff(v)).mean())


def run_setup(dev, st, setup, key, iv):
    for h, sizes in setup:
        c = bytearray(bytes.fromhex(h))
        if len(c) == ARM_LEN:
            c[KEY_OFF:KEY_OFF + 32] = key
            c[IV_OFF:IV_OFF + 16] = iv
        reply = S.command(dev, st, bytes(c))
        for n in sizes:
            dev.read(S.EP_DATA_IN, n, 3000)
        if reply[:2] != b"\x00\x00":
            raise RuntimeError("setup command %s rejected: %s" % (h[:2], reply[:4].hex()))


def wait_finger(dev, st, timeout):
    t_end = time.monotonic() + timeout
    while time.monotonic() < t_end:
        r = S.command(dev, st, b"\x17")       # GetFingerState: byte 2 bit 1 = finger present
        if len(r) > 2 and r[2] & 0x02:
            return True
        time.sleep(0.05)
    return False


def read_swipe(dev, key, iv, perm):
    """Stream + decrypt the swipe; returns the raw (scrambled) pixel lines as an (n, 264) uint8 array."""
    inv = np.argsort(perm)                    # inv[p] = raw position of descrambled column p
    inv_main = inv[:MAIN]
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    buf, lines, peak, quiet = b"", [], 0.0, 0
    t0 = time.monotonic()
    while time.monotonic() - t0 < MAX_SWIPE_S:
        try:
            chunk = bytes(dev.read(S.EP_DATA_IN, 16384, READ_TIMEOUT_MS))
        except usb.core.USBTimeoutError:
            break                             # the sensor ended the stream: finger gone
        buf += dec.update(chunk)
        while len(buf) >= FRAME:
            f, buf = buf[:FRAME], buf[FRAME:]
            if f[:2] != b"\x01\xfe":
                continue
            px = np.frombuffer(f[HDR:], np.uint8)
            e = line_energy(px, inv_main)
            peak = max(peak, e)
            quiet = quiet + 1 if e < QUIET_FRAC * peak else 0
            lines.append(px)
        if len(lines) > 2 * QUIET_LINES and quiet >= QUIET_LINES:
            break
    return np.array(lines) if lines else np.zeros((0, WIDTH), np.uint8)


def stop_stream(dev, st):
    """04 AbortFingerprint, drain what is still queued, consume the reply (keeps the SSL state in sync)."""
    S.send(dev, st.encrypt_record(0x17, b"\x04"))
    try:
        while True:
            dev.read(S.EP_DATA_IN, 16384, 300)
    except usb.core.USBError:
        pass
    try:
        for typ, body in S.split_records(S.recv(dev, 0x400, 1000)):
            st.decrypt_record(typ, body)
    except usb.core.USBError:
        pass


def to_image(raw, perm):
    img = np.zeros((len(raw), WIDTH), np.uint8)
    img[:, perm] = raw                        # descramble: out[perm[i]] = raw[i]
    return vfs495_assemble.assemble(img)


def report_finger_on():
    """Tell libfprint's virtual_image (VFS_FINGER_SOCK, set by the bridge) the finger is on, as (-4, 1),
    so fprintd's finger-present goes true at swipe start (same as HP's harvest_assembled.py)."""
    sock = os.environ.get("VFS_FINGER_SOCK")
    if not sock:
        return
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(sock)
        s.sendall(struct.pack("<ii", -4, 1))
        s.close()
    except OSError:
        pass


def main():
    # the bridge cancels a capture with SIGTERM: unwind through the finally blocks so the sensor
    # session is closed (close_notify) instead of being left open
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    if len(sys.argv) < 2:
        sys.exit("usage: vfs495_native_capture.py OUT.pgm")
    out = sys.argv[1]
    init = [bytes.fromhex(h) for h in json.load(open(CAP + "/init_cmds.json"))]
    setup = json.load(open(CAP + "/capture_cmds.json"))
    perm = descramble_table()
    key, iv = secrets.token_bytes(32), secrets.token_bytes(16)
    dev, st = S.open_session(init)
    try:
        run_setup(dev, st, setup, key, iv)
        print("swipe now", file=sys.stderr, flush=True)
        if not wait_finger(dev, st, float(os.environ.get("VFS_TIMEOUT", "60"))):
            print("no finger captured", file=sys.stderr)
            return 10
        report_finger_on()
        raw = read_swipe(dev, key, iv, perm)
        stop_stream(dev, st)
    finally:
        S.close_session(dev, st)
        S.close_device(dev)
    if len(raw) < MIN_LINES:
        print("swipe too short (%d lines)" % len(raw), file=sys.stderr)
        return 10
    if os.environ.get("VFS_RAW"):
        with os.fdopen(os.open(os.environ["VFS_RAW"], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as f:
            np.save(f, raw)
    img = to_image(raw, perm)
    with open(out, "wb") as f:
        f.write(f"P5\n{img.shape[1]} {img.shape[0]}\n255\n".encode())
        f.write(np.ascontiguousarray(img).tobytes())
    print(f"captured {img.shape[1]}x{img.shape[0]} ({len(raw)} lines) -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
