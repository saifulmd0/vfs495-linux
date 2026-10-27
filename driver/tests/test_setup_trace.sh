#!/usr/bin/env bash
# T2 check: runtime/trace_to_init.py recovers init_cmds.json + capture_cmds.json from a usblog trace.
# Builds synthetic traces of an HP run from the recorded commands (random session key block), runs the
# extractor and compares. Endpoints are logged both as 0x82/0x81 and as libusb-0.1 callers may pass them
# (2/1: libusb adds the direction bit). A wrong key block and a trace without data reads must be rejected.
#   driver/tests/test_setup_trace.sh [CAPTURES_DIR]       (python3 + cryptography + pyusb)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
cap=${1:-$here/../../captures}
extract=$here/../../runtime/trace_to_init.py
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
python3 - "$here/../../tools" "$cap" "$tmp" <<'PY'
import json, secrets, struct, sys
sys.path.insert(0, sys.argv[1])
import ssl_session as S
cap, tmp = sys.argv[2], sys.argv[3]
init = json.load(open(cap + "/init_cmds.json"))
setup = json.load(open(cap + "/capture_cmds.json"))


def trace(name, kb, data_ep, cmd_ep, with_reads):
    st = S.SSLState(kb)
    lines = []
    def out(d): lines.append("1.0 OUT ep=01 len=%d ret=%d data=%s" % (len(d), len(d), d.hex()))
    def inp(ep, ret, d=b""): lines.append("1.0 IN  ep=%02x req=16384 ret=%d data=%s" % (ep, ret, d.hex()))
    for i, h in enumerate(init):
        out(bytes.fromhex(h)); inp(cmd_ep, 2, b"\0\0")
        if i == 1:
            out(b"\x1a"); inp(cmd_ep, 2, b"\0\0")    # HP's unload: must not end up in init_cmds.json
    inp(data_ep, 4096, b"\0" * 8)                    # plaintext flash read: not a setup read
    ch = b"\x01\x00\x00\x33\x03\x00" + bytes(32) + b"\x07" + bytes(7) + b"\x00\x06\x00\x44\x00\x43\x00\x42\x00"
    rec = b"\x16\x03\x00" + struct.pack(">H", len(ch)) + ch
    out(b"\x11" + struct.pack("<H", len(rec)) + rec); inp(cmd_ep, 80, bytes(80))
    cke = b"\x10\x00\x01\x00" + secrets.token_bytes(256)
    flight = (b"\x16\x03\x00" + struct.pack(">H", len(cke)) + cke + b"\x14\x03\x00\x00\x01\x01"
              + st.encrypt_record(0x16, b"\x14\x00\x00\x24" + secrets.token_bytes(36)))
    out(b"\x11" + struct.pack("<H", len(flight)) + flight); inp(cmd_ep, 60, bytes(60))
    out(st.encrypt_record(0x17, b"\x01")); inp(cmd_ep, 64, bytes(64))     # a GetVersion first: skipped
    for h, reads in setup:
        out(st.encrypt_record(0x17, bytes.fromhex(h))); inp(cmd_ep, 32, bytes(32))
        for n in reads if with_reads else []:
            inp(data_ep, n, b"\xaa" * 4)
        if reads:
            inp(data_ep, -110)                       # a timed-out read: ignored
    for _ in range(3):
        out(st.encrypt_record(0x17, b"\x17")); inp(cmd_ep, 32, bytes(32))  # finger polls after arming
    open("%s/%s.log" % (tmp, name), "w").write("\n".join(lines) + "\n")


kb = secrets.token_bytes(136)
json.dump({"keyblock": kb.hex()}, open(tmp + "/kb.json", "w"))
json.dump({"keyblock": secrets.token_bytes(136).hex()}, open(tmp + "/bad.json", "w"))
trace("ep82", kb, 0x82, 0x81, True)
trace("ep02", kb, 0x02, 0x01, True)
trace("noreads", kb, 0x82, 0x81, False)
PY
for t in ep82 ep02; do
  echo "trace $t:"
  python3 "$extract" "$tmp/$t.log" "$tmp/$t" --keyblock "$tmp/kb.json" >/dev/null
  python3 - "$cap" "$tmp/$t" <<'PY'
import json, sys
for name in ("init_cmds.json", "capture_cmds.json"):
    a, b = json.load(open(sys.argv[1] + "/" + name)), json.load(open(sys.argv[2] + "/" + name))
    if a != b:
        sys.exit("FAIL: %s differs (%d vs %d entries)" % (name, len(a), len(b)))
    print("  %s identical (%d entries)" % (name, len(a)))
PY
done
reject() {   # reject NAME TRACE KEYBLOCK
  if python3 "$extract" "$tmp/$2.log" "$tmp/x" --keyblock "$tmp/$3" >/dev/null 2>"$tmp/err"; then
    echo "FAIL: $1 accepted"; exit 1
  fi
  echo "$1 rejected: $(cat "$tmp/err")"
}
reject "wrong key block" ep82 bad.json
reject "trace without data reads" noreads kb.json
echo OK
