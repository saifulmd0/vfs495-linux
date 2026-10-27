#!/usr/bin/env python3
"""VFS495 proprietary-SSLv3 client: open the sensor's secure session without HP's binary.

Implements docs/SSL_PROTOCOL.md. Verified on hardware (2026-10-09): handshake accepted, the sensor's
Finished verifies, and commands sent inside the session get valid encrypted replies.

Needs captures/init_cmds.json: the pre-SSL init sequence (GetVersion, GetStartInfo, the two firmware
patches, SPI flash reads). The patches are HP's and are not redistributed; extract them once from a USB
trace of HP's binary with runtime/trace_to_init.py. The RSA session key is read from the sensor's own
flash (storage id 10) during init. Patches go to sensor RAM only.

Run: sudo python3 ssl_session.py      (opens a session and sends one encrypted GetVersion)
"""
import json
import os
import struct
import sys
import time

import hashlib
import secrets

import usb.core
import usb.util
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HERE = os.path.dirname(os.path.abspath(__file__))
CAP = os.environ.get("VFS495_CAPTURES", HERE + "/../captures")
VID, PID = 0x138A, 0x003F
EP_OUT, EP_CMD_IN, EP_DATA_IN = 0x01, 0x81, 0x82
INIT_PAUSE = 0.03   # HP pauses up to ~30 ms between init commands; back-to-back the sensor resets
LABEL_CLNT = struct.pack("<I", 0x434C4E54)   # Finished labels are hashed as LE ints
LABEL_SRVR = struct.pack("<I", 0x53525652)


# ---- crypto ---------------------------------------------------------------
def ssl3_prf(secret, seed_a, seed_b, nbytes):
    out, i = b"", 0
    while len(out) < nbytes:
        salt = bytes([0x41 + i]) * (i + 1)
        out += hashlib.md5(secret + hashlib.sha1(salt + secret + seed_a + seed_b).digest()).digest()
        i += 1
    return out[:nbytes]


def rsa_encrypt(modulus_le, exp, msg):
    """PKCS#1 v1.5 type 2. Modulus is stored little-endian; message and wire ciphertext are big-endian."""
    n = int.from_bytes(modulus_le, "little")
    k = len(modulus_le)
    ps = b""
    while len(ps) < k - 3 - len(msg):
        b = secrets.token_bytes(1)
        if b != b"\x00":
            ps += b
    em = b"\x00\x02" + ps + b"\x00" + msg
    return pow(int.from_bytes(em, "big"), exp, n).to_bytes(k, "big")


def ssl3_finished(master, handshake_msgs, label):
    def h(algo, pad_len):
        pad1 = b"\x36" * pad_len
        pad2 = b"\x5c" * pad_len
        inner = algo(handshake_msgs + label + master + pad1).digest()
        return algo(master + pad2 + inner).digest()
    return h(hashlib.md5, 48) + h(hashlib.sha1, 40)


class SSLState:
    def __init__(self, keyblock):
        self.cmac = keyblock[0:20]
        self.smac = keyblock[20:40]
        self.ckey = keyblock[40:72]
        self.skey = keyblock[72:104]
        self.civ = keyblock[104:120]
        self.siv = keyblock[120:136]
        self.send_seq = 0
        self.recv_seq = 0

    def mac(self, key, seq, rtype, data):
        # Validity SSLv3 MAC variant: length is NOT included (only seq + type + data).
        pad1, pad2 = b"\x36" * 40, b"\x5c" * 40
        hdr = struct.pack(">Q", seq) + bytes([rtype])
        inner = hashlib.sha1(key + pad1 + hdr + data).digest()
        return hashlib.sha1(key + pad2 + inner).digest()

    def encrypt_record(self, rtype, data):
        m = self.mac(self.cmac, self.send_seq, rtype, data)
        self.send_seq += 1
        body = data + m
        padlen = 16 - (len(body) % 16)
        body += bytes([padlen - 1]) * padlen
        enc = Cipher(algorithms.AES(self.ckey), modes.CBC(self.civ)).encryptor()
        ct = enc.update(body) + enc.finalize()
        self.civ = ct[-16:]  # SSLv3 CBC IV chaining
        return bytes([rtype, 3, 0]) + struct.pack(">H", len(ct)) + ct

    def decrypt_record(self, rtype, ct):
        """Sensor -> host record body: returns (data, mac_ok)."""
        dec = Cipher(algorithms.AES(self.skey), modes.CBC(self.siv)).decryptor()
        p = dec.update(ct) + dec.finalize()
        self.siv = ct[-16:]
        p = p[:len(p) - p[-1] - 1]
        data, m = p[:-20], p[-20:]
        ok = self.mac(self.smac, self.recv_seq, rtype, data) == m
        self.recv_seq += 1
        return data, ok


def split_records(buf):
    """[(type, body)] for back-to-back SSL records."""
    out, p = [], 0
    while p + 5 <= len(buf):
        n = int.from_bytes(buf[p + 3:p + 5], "big")
        out.append((buf[p], buf[p + 5:p + 5 + n]))
        p += 5 + n
    return out


def flash_storage(flash, want, base=0x1000):
    """Entry `want` of the storage table in the 4 KiB flash block that init reads (flash 0x1000..0x1fff):
    'EAT"' header, then from byte 13 entries of ff <id> <u32 addr LE> <u32 size LE>."""
    p = 13
    while p + 10 <= len(flash) and flash[p] == 0xFF:
        sid, addr, size = flash[p + 1], *struct.unpack_from("<II", flash, p + 2)
        if sid == want and 0 <= addr - base and addr - base + size <= len(flash):
            return flash[addr - base:addr - base + size]
        p += 10
    return None


# ---- usb ------------------------------------------------------------------
TRAFFIC = []
def send(dev, payload, to=3000):
    TRAFFIC.append(("OUT", bytes(payload).hex(), time.monotonic()))
    dev.write(EP_OUT, bytes(payload), to)


def recv(dev, n=0x400, to=3000, ep=EP_CMD_IN):
    r = bytes(dev.read(ep, n, to))
    TRAFFIC.append(("IN%02x" % ep, r.hex(), time.monotonic()))
    return r


def tunnel(record):
    return bytes([0x11]) + struct.pack("<H", len(record)) + record


def open_device():
    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if dev is None:
        sys.exit("VFS495 not found")
    try:
        if dev.get_active_configuration().bConfigurationValue != 1:
            dev.set_configuration(1)
    except usb.core.USBError:
        dev.set_configuration(1)   # libusb refuses to re-set an active configuration on Linux
    usb.util.claim_interface(dev, 0)
    return dev


def close_device(dev):
    try:
        usb.util.release_interface(dev, 0)
    except usb.core.USBError:
        pass   # the sensor re-enumerates after a fatal alert
    usb.util.dispose_resources(dev)


class StaleSession(Exception):
    """The sensor still holds an SSL session from a previous process; it resets itself after this."""


# ---- protocol -------------------------------------------------------------
def init_sensor(dev, init):
    """Replay the pre-SSL init. Returns the 4 KiB flash block (holds the storage table)."""
    flash = b""
    for c in init:
        time.sleep(INIT_PAUSE)
        send(dev, c)
        r = recv(dev)
        if r[:1] == b"\x15":
            raise StaleSession()
        if c == b"\x01" and len(r) > 17 and r[17] and not flash:
            # patches still loaded (e.g. after a clean close): unload first, like HP does
            time.sleep(INIT_PAUSE)
            send(dev, b"\x1a")
            recv(dev)
        if c[0] == 0x1F:                       # SPI flash read: data follows on ep 0x82
            size = struct.unpack_from("<I", c, 5)[0]
            # read exactly `size`: the sensor sends full 64 B packets and no short packet
            data = recv(dev, size, 1000, EP_DATA_IN)
            if size == 0x1000:
                flash = data
    return flash


def handshake(dev, modulus):
    """SSLv3 handshake (docs/SSL_PROTOCOL.md). Returns the session state; raises on an alert."""
    client_random = secrets.token_bytes(32)
    # ClientHello: SSL 3.0, 7-byte zero session id, suites 0x0044/43/42 (AES-256/192/128-CBC-SHA)
    ch_hs = (b"\x01\x00\x00\x33\x03\x00" + client_random + b"\x07" + bytes(7)
             + b"\x00\x06\x00\x44\x00\x43\x00\x42\x00")
    rec_ch = b"\x16\x03\x00" + struct.pack(">H", len(ch_hs)) + ch_hs
    # RSA before sending: keep the ServerHello -> flight gap short
    premaster = b"\x03\x00" + secrets.token_bytes(46)
    cke_hs = b"\x10\x00\x01\x00" + rsa_encrypt(modulus, 0x10001, premaster)
    cke_rec = b"\x16\x03\x00" + struct.pack(">H", len(cke_hs)) + cke_hs
    send(dev, tunnel(rec_ch))
    sh = recv(dev)
    if sh[:1] != b"\x16":
        raise RuntimeError("no ServerHello: " + sh.hex())
    sh_hs = sh[5:5 + int.from_bytes(sh[3:5], "big")]   # ServerHello + ServerHelloDone
    server_random = sh[11:43]

    master = ssl3_prf(premaster, client_random, server_random, 48)
    st = SSLState(ssl3_prf(master, server_random, client_random, 136))
    hs_msgs = ch_hs + sh_hs + cke_hs
    fin_hs = b"\x14\x00\x00\x24" + ssl3_finished(master, hs_msgs, LABEL_CLNT)
    send(dev, tunnel(cke_rec + b"\x14\x03\x00\x00\x01\x01" + st.encrypt_record(0x16, fin_hs)))
    resp = recv(dev)
    if resp[:1] == b"\x15":
        raise RuntimeError("sensor alert 0x%02x" % resp[-1])
    # the sensor's Finished covers the SAME msgs as ours: our Finished is not hashed in (Validity variant)
    want = ssl3_finished(master, hs_msgs, LABEL_SRVR)
    verified = False
    for typ, body in split_records(resp):
        if typ == 0x14:
            continue                                  # ChangeCipherSpec
        data, ok = st.decrypt_record(typ, body)
        if not ok:
            raise RuntimeError("bad MAC on sensor record type %#x" % typ)
        if typ == 0x16:
            verified = data[4:] == want
    if not verified:
        raise RuntimeError("sensor Finished did not verify")
    return st


def command(dev, st, payload, reply=0x4000, to=3000):
    """Send one VCSFW command inside the session (AppData record); return the decrypted reply."""
    send(dev, st.encrypt_record(0x17, payload), to)
    out = b""
    for typ, body in split_records(recv(dev, reply, to)):
        if typ == 0x15 and len(body) % 16:            # plaintext alert: the sensor dropped the session
            raise RuntimeError("sensor alert " + body.hex())
        data, ok = st.decrypt_record(typ, body)
        if not ok:
            raise RuntimeError("bad MAC on reply")
        out += data
    return out


def close_session(dev, st):
    """End the session like HP does on exit: encrypted close_notify alert (01 00), the sensor answers
    with its own. Without this the sensor keeps the session after we exit and rejects the next client
    (it then resets itself, which costs a re-enumeration). Returns True if the sensor confirmed."""
    try:
        send(dev, st.encrypt_record(0x15, b"\x01\x00"))
        for typ, body in split_records(recv(dev, 0x400, 1000)):
            if typ == 0x15 and len(body) % 16 == 0:
                data, ok = st.decrypt_record(typ, body)
                return ok and data == b"\x01\x00"
    except usb.core.USBError:
        pass
    return False


def open_session(init, attempts=2):
    """Open the device, init and handshake. Retries once if a stale session made the sensor reset."""
    for attempt in range(attempts):
        dev = open_device()
        try:
            flash = init_sensor(dev, init)
            modulus = flash_storage(flash, 10)        # RSA session key = storage id 10
            if modulus is None:
                raise RuntimeError("RSA key (storage id 10) not found in sensor flash")
            return dev, handshake(dev, modulus)
        except (StaleSession, usb.core.USBError):
            old = dev.address
            close_device(dev)
            if attempt == attempts - 1:
                raise
            print("sensor still held an old session and reset itself; retrying", file=sys.stderr)
            deadline = time.monotonic() + 10          # wait until it re-enumerates (new address)
            while time.monotonic() < deadline:
                new = usb.core.find(idVendor=VID, idProduct=PID)
                if new is not None and new.address != old:
                    break
                time.sleep(0.2)
            time.sleep(0.5)
        except Exception:
            close_device(dev)
            raise


def main():
    init = [bytes.fromhex(h) for h in json.load(open(CAP + "/init_cmds.json"))]
    dev, st = open_session(init)
    try:
        print("session open: handshake OK, sensor Finished verified")
        print("GetVersion (encrypted):", command(dev, st, b"\x01").hex())
    finally:
        print("session closed:", "sensor confirmed" if close_session(dev, st) else "NOT confirmed")
        json.dump(TRAFFIC, open(CAP + "/my_session.json", "w"))
        close_device(dev)


if __name__ == "__main__":
    main()
