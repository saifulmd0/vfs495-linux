#!/usr/bin/env python3
"""Extract the sensor's per-device commands from a usblog.c trace of ONE run of HP's binary.
One-time; the output stays local (it is HP's per-device data, never redistribute it).

    trace_to_init.py usb.log init_cmds.json                     init sequence only (before the session)
    trace_to_init.py usb.log CAPTURES_DIR --keyblock kb.json    + the setup commands (capture_cmds.json)

init_cmds.json: the plaintext commands before the ClientHello (GetVersion, the firmware patches, flash
reads), for tools/ssl_session.py and the driver.
capture_cmds.json: [[command hex, [ep 0x82 read sizes]], ...], HP's commands inside the session, decrypted,
from the first one after GetVersion through the arming command (02, 3033 B). Needs the session key block
(136 B: client/server MAC, key, IV), dumped from HP's process by runtime/dump_keyblock.py in the same run.

    sudo VFSLOG=usb.log LD_PRELOAD=$PWD/lib/usblog.so LD_LIBRARY_PATH=$PWD/lib \\
        gdb -batch -x dump_keyblock.py bin/validity-sensor-unlocked      (runtime/vfs495-setup does all this)
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../tools"))

ARM_LEN = 3033      # the arming command carries the image key (tools/make_setup_bin.py)
LINE = re.compile(r"^\S+ (OUT|IN) +ep=([0-9a-f]{2}) (?:len|req)=\d+ ret=(-?\d+) data=([0-9a-f]*)$")


def parse(path):
    """[(dir, ep, ret, bytes)] of the bulk transfers in a usblog trace. ep without the direction bit:
    libusb-0.1 adds it itself, so HP may pass 2 or 0x82 for the data endpoint."""
    out = []
    for line in open(path):
        m = LINE.match(line.strip())
        if m:
            out.append((m[1], int(m[2], 16) & 0x7f, int(m[3]), bytes.fromhex(m[4])))
    return out


def init_cmds(trace):
    outs = [d for di, ep, _, d in trace if di == "OUT" and ep == 1]
    try:
        end = next(i for i, d in enumerate(outs) if d[:3] == b"\x11\x3c\x00")   # the ClientHello tunnel
    except StopIteration:
        sys.exit("no ClientHello in the trace: let HP's binary run longer")
    # 1a (UnloadPatch) only appears when the sensor still had a patch loaded; the driver handles that itself
    return [d.hex() for d in outs[:end] if d != b"\x1a"]


def setup_cmds(trace, keyblock):
    """HP's decrypted in-session commands with the ep 0x82 reads after each, through the arming command."""
    import ssl_session as S

    st = S.SSLState(keyblock)
    cmds, started = [], False
    for di, ep, ret, d in trace:
        if di == "IN" and ep == 2 and ret > 0 and cmds:
            cmds[-1][1].append(ret)
            continue
        if di != "OUT" or ep != 1:
            continue
        if not started:
            # the flight, tunnelled (11 <u16 len>): ClientKeyExchange, ChangeCipherSpec, encrypted Finished
            records = S.split_records(d[3:]) if d[:1] == b"\x11" else []
            types = [t for t, _ in records]
            if 0x14 not in types:
                continue
            records = records[types.index(0x14) + 1:]
            started = True
        else:
            records = S.split_records(d)
        for typ, body in records:
            # client -> sensor: decrypt with the client keys (SSLState's decrypt_record uses the server's)
            st.skey, st.siv, st.smac, st.recv_seq = st.ckey, st.civ, st.cmac, st.send_seq
            data, ok = st.decrypt_record(typ, body)
            st.civ, st.send_seq = st.siv, st.recv_seq
            if not ok:
                sys.exit("bad MAC on HP's record %d: wrong key block for this trace?" % (st.send_seq - 1))
            if typ == 0x17:
                cmds.append([data, []])
        if cmds and cmds[-1][0][:1] == b"\x02" and len(cmds[-1][0]) == ARM_LEN:
            break
    if not started:
        sys.exit("no handshake in the trace")
    if not cmds or len(cmds[-1][0]) != ARM_LEN:
        sys.exit("no arming command (02, %d B) in the trace: let HP's binary run longer" % ARM_LEN)
    if not any(r for _, r in cmds):
        sys.exit("no ep 0x82 data reads in the trace: the setup would desync the sensor (trace format?)")
    # the driver sends its own encrypted GetVersion after the handshake; setup starts after HP's
    first = next((i for i, (c, _) in enumerate(cmds) if c[:1] != b"\x01"), len(cmds))
    skipped = [c[:1].hex() for c, _ in cmds[:first]]
    return [[c.hex(), r] for c, r in cmds[first:]], skipped


def main():
    a = sys.argv[1:]
    if len(a) == 2:
        init = init_cmds(parse(a[0]))
        json.dump(init, open(a[1], "w"))
        print("init:", " ".join(h[:2] for h in init), "->", a[1])
        return
    if len(a) != 4 or a[2] != "--keyblock":
        sys.exit(__doc__)
    trace, out = parse(a[0]), a[1]
    keyblock = bytes.fromhex(json.load(open(a[3]))["keyblock"])
    if len(keyblock) != 136:
        sys.exit("key block must be 136 B")
    init = init_cmds(trace)
    setup, skipped = setup_cmds(trace, keyblock)
    os.makedirs(out, mode=0o700, exist_ok=True)
    for name, obj in (("init_cmds.json", init), ("capture_cmds.json", setup)):
        with os.fdopen(os.open(os.path.join(out, name), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
            json.dump(obj, f)
    print("init:", " ".join(h[:2] for h in init))
    print("setup:", " ".join(h[:2] for h, _ in setup), "(skipped before:", " ".join(skipped) or "-", ")")
    print("->", out)


if __name__ == "__main__":
    main()
