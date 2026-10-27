#!/usr/bin/env python3
"""Pack the sensor's init/setup commands into the single file the libfprint driver reads.

    python3 make_setup_bin.py [--minimal] [CAPTURES_DIR] OUT.bin      (default dir: ../captures)
    sudo install -m600 OUT.bin /var/lib/vfs495/setup.bin

--minimal (EXPERIMENTAL, T7 probe step M, docs/FINDINGS.md "T7 run 10"): only HP's two init patches (693 +
1301 B). Setup without its patch uploads (06) and unloads (1a), without the 2666 B config, and the 2691 / 3033 B
configs without TLV types 23 and 27. The probe captured with it; not yet measured with the driver.

Input: init_cmds.json (runtime/trace_to_init.py) and capture_cmds.json (HP's setup commands, decrypted
from one traced HP session). Both are HP's per-device data; the output stays local, never redistribute it.

Format (little endian), parsed by driver/vfs495_setup.c:
    "VFS495S1"
    u16 n_init,  then n_init  x { u32 len, len bytes }                    plaintext, before the session
    u16 n_setup, then n_setup x { u8 flags, u32 len, len bytes,           encrypted, before each swipe
                                  u16 n_reads, n_reads x u32 size }       ep 0x82 reads after the reply
    flags bit 0: the arming command (the last 02 config); the driver writes a fresh image key + IV into the
                 first 48 B of its type-6 TLV (offset 2927 in HP's 3033 B one)
"""
import json
import os
import struct
import sys

MAGIC = b"VFS495S1"
ARM_LEN = 3033      # HP's arming command (02, 3033 B) carries the image key (vfs495_native_capture.py)
MINIMAL_STRIP = {2691: (23, 27), 3033: (23, 27)}   # TLV types the ROM lacks (they need the 2581 B patch)


def tlvs(cfg):
    """[(type, payload)] of an 02 config (5 B header, then u16le type, u16le length, payload)."""
    out, o = [], 5
    while o < len(cfg):
        t, n = struct.unpack_from("<HH", cfg, o)
        if o + 4 + n > len(cfg):
            raise ValueError("TLV at %d overruns the config" % o)
        out.append((t, cfg[o + 4:o + 4 + n]))
        o += 4 + n
    return out


def minimal(setup):
    """HP's setup reduced to what probe step M ran: see --minimal above."""
    out = []
    for h, reads in setup:
        c = bytes.fromhex(h)
        if c[:1] in (b"\x06", b"\x1a") or (c[:1] == b"\x02" and len(c) == 2666):
            continue
        if c[:1] == b"\x02" and len(c) in MINIMAL_STRIP:
            c = c[:5] + b"".join(struct.pack("<HH", t, len(p)) + p for t, p in tlvs(c)
                                 if t not in MINIMAL_STRIP[len(c)])
        out.append((c.hex(), reads))
    return out


def arming_index(setup):
    """The arming command: the last 02 config, which must carry a type-6 key block."""
    i = max(i for i, (h, _) in enumerate(setup) if h[:2] == "02")
    if not any(t == 6 and len(p) >= 48 for t, p in tlvs(bytes.fromhex(setup[i][0]))):
        sys.exit("the last config (setup command %d) has no type-6 key block" % i)
    return i


def pack(init, setup):
    arm = arming_index(setup)
    out = bytearray(MAGIC)
    out += struct.pack("<H", len(init))
    for h in init:
        c = bytes.fromhex(h)
        out += struct.pack("<I", len(c)) + c
    out += struct.pack("<H", len(setup))
    for i, (h, reads) in enumerate(setup):
        c = bytes.fromhex(h)
        out += struct.pack("<BI", 1 if i == arm else 0, len(c)) + c
        out += struct.pack("<H", len(reads)) + b"".join(struct.pack("<I", n) for n in reads)
    return bytes(out)


def main():
    args = sys.argv[1:]
    small = "--minimal" in args
    args = [a for a in args if a != "--minimal"]
    if len(args) not in (1, 2):
        sys.exit(__doc__)
    cap = args[0] if len(args) == 2 else os.path.dirname(os.path.abspath(__file__)) + "/../captures"
    init = json.load(open(cap + "/init_cmds.json"))
    setup = json.load(open(cap + "/capture_cmds.json"))
    if sum(len(bytes.fromhex(h)) == ARM_LEN for h, _ in setup) != 1:
        sys.exit("expected exactly one arming command (%d B) in capture_cmds.json" % ARM_LEN)
    if small:
        setup = minimal(setup)
    data = pack(init, setup)
    with os.fdopen(os.open(args[-1], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as f:
        f.write(data)
    print("%d init + %d setup commands%s, %d B -> %s" % (len(init), len(setup), " (minimal)" if small else "",
                                                         len(data), args[-1]))


if __name__ == "__main__":
    main()
