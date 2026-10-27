#!/usr/bin/env bash
# T7 check: tools/probe_patches.py's VFS495_PROBE_DUMP and tools/compare_probe_dumps.py, without a sensor.
# Runs variants G and H against a mock sensor (USB and SSL replaced; setup commands, the dump code, the
# swipe stream recording and decryption are the real ones). The mock answers the 2691 B configs with extra
# bytes, sends type-6-encrypted 01fe frames after the 2331 / 2691 B configs, plaintext after the others, and a
# swipe encrypted with the arming key. Without the 405 B patch (G) it shifts the baseline and lowers the
# contrast, so the comparison must report a difference; G vs G must report none in the setup reads.
#   driver/tests/test_probe_dump.sh [CAPTURES_DIR]       (python3 + numpy + cryptography + pyusb)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
tools=$here/../../tools
export VFS495_CAPTURES=${1:-$here/../../captures}
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/dump"
VFS495_PROBE_DUMP=$tmp/dump VFS495_PROBE_SWIPES=2 python3 - "$tools" <<'PY'
import json, os, sys
import numpy as np
import usb.core
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
sys.path.insert(0, sys.argv[1])
import probe_patches as P
S, N = P.S, P.N
P.FINGER_WAIT = 2
rng = np.random.default_rng(1)
PERM = N.descramble_table()


def enc(key, iv, data):
    return Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor().update(data)


def frames(n, base, contrast, ridges):
    out = b""
    for i in range(n):
        line = np.full(N.WIDTH, base, float)
        if ridges:
            line += contrast * np.sin(np.arange(N.WIDTH) * 0.6 + i * 0.1)
        line += rng.normal(0, 2, N.WIDTH)
        px = np.clip(line, 0, 255).astype(np.uint8)
        raw = px[PERM]                                  # scramble: out[perm[i]] = raw[i]
        out += b"\x01\xfe" + bytes([i & 0xff, 0, 0, 0, 0, 0]) + raw.tobytes()
    return out


class Sensor:
    def __init__(self):
        self.patch405 = False
        self.reads, self.polls, self.swipe = [], 0, []
        self.address = 7

    def base(self):
        return (120, 40) if self.patch405 else (95, 25)

    def read(self, ep, n, to):                          # only read_swipe reads the device directly
        if not self.swipe:
            raise usb.core.USBTimeoutError("timeout")
        return self.swipe.pop(0)


class St:
    pass


def pcmd(dev, st, c, res):
    if c[:1] == b"\x06" and len(c) == 405:
        dev.patch405 = True
    if c[:1] == b"\x1a":
        dev.patch405 = False
    if c == b"\x17":
        dev.polls += 1
        return b"\x00\x00" + (b"\x02" if dev.polls % 4 == 0 else b"\x00") + b"\x09\x40\x00"
    if c[:1] == b"\x02":
        b, k = dev.base()
        k6 = P.key6(c)
        if any(t == 24 for t, _ in P.tlvs(c)[1]):       # the arming config (stripped or not)
            key, iv = k6
            s = enc(key, iv, frames(600, b, k, True) + frames(200, b, k, False))
            dev.swipe = [s[o:o + 16384] for o in range(0, len(s), 16384)]
            dev.reads = []
        elif k6:
            fr = frames(21, b, k, False)
            dev.reads = [enc(k6[0], k6[1], fr)]
        else:
            dev.reads = [bytes([b & 0xff]) * 64]
        return b"\x00\x00" + (bytes(range(256)) * 10)[:2400] if len(c) == 2691 else b"\x00\x00"
    dev.reads = []
    return b"\x00\x00"


def recv(dev, n=0x400, to=3000, ep=S.EP_CMD_IN):
    if ep != S.EP_DATA_IN:                              # plain_stop reads the 04 reply
        return b"\x00\x00"
    return dev.reads.pop(0) if dev.reads else bytes(n)


# set_key6 puts the key where the driver does (offsets 2927 / 2959 of the recorded 3033 B config)
arm = [bytes.fromhex(h) for h, _ in json.load(open(S.CAP + "/capture_cmds.json")) if len(h) // 2 == N.ARM_LEN][0]
k, v = os.urandom(32), os.urandom(16)
assert P.set_key6(arm, k, v) == arm[:N.KEY_OFF] + k + arm[N.KEY_OFF + 32:N.IV_OFF] + v + arm[N.IV_OFF + 16:]
assert P.key6(P.set_key6(P.strip_tlvs(arm, (23, 27)), k, v)) == (k, v)

# the real pcmd in plaintext (step P): sends the bare command, returns the bare reply
sent = []
S.send, S.recv = (lambda dev, c, to=3000: sent.append(c)), (lambda dev, n=0, to=0, ep=0: b"\x00\x00ab")
assert P.pcmd(None, P.Plain(), b"\x01", {}) == b"\x00\x00ab" and sent == [b"\x01"]
S.send = lambda dev, c, to=3000: None
P.pcmd = pcmd
P.init_tolerant = lambda dev, init, res: b"flash"
S.flash_storage = lambda flash, want: b"mod"
S.open_device = Sensor
S.close_device = lambda dev: None
S.handshake = lambda dev, mod: St()
S.close_session = lambda dev, st: True
S.recv = recv
N.stop_stream = lambda dev, st: None
init = [bytes.fromhex(h) for h in json.load(open(S.CAP + "/init_cmds.json"))]
setup = [(bytes.fromhex(h), r) for h, r in json.load(open(S.CAP + "/capture_cmds.json"))]
for w in "UPM":                                        # stripped configs: the swipe still decrypts
    res = P.run_variant(w, init, setup)
    print(w, res["result"], res.get("getversion"))
    assert res["swipe 1"].startswith("800 decrypted lines"), res
    assert "handshake" not in res if w == "P" else res["handshake"] == "ok", res
    os.unlink(res["dump"])
for w in "GHG":
    res = P.run_variant(w, init, setup)
    print(w, res["result"], res.get("dump"))
    assert res["swipe 1"].startswith("800 decrypted lines") and res["swipe 2"].startswith("800 "), res  # synthetic: no motion, so no 80-row print
    assert oct(os.stat(res["dump"]).st_mode & 0o777) == "0o600"
    import time; time.sleep(1.1)                         # one dump per second (file name)
PY
ls "$tmp/dump"
dumps=("$tmp"/dump/dump-*.json)
[ ${#dumps[@]} -eq 3 ] || { echo "FAIL: expected 3 dumps"; exit 1; }
g=$(ls "$tmp"/dump/dump-G-*.json | head -1); h=$(ls "$tmp"/dump/dump-H-*.json)
python3 "$tools/compare_probe_dumps.py" "$g" "$h" > "$tmp/gh.txt"
cat "$tmp/gh.txt"
grep -q '^06(405) #1' "$tmp/gh.txt"                                   || { echo "FAIL: 405 B patch row"; exit 1; }
grep -A2 '^02(2691) #1' "$tmp/gh.txt" | grep -q '+2400 B'             || { echo "FAIL: 2691 B extra reply"; exit 1; }
grep -A2 '^02(2331) #1' "$tmp/gh.txt" | grep -q '21 01fe frames'      || { echo "FAIL: 2331 B read decrypt"; exit 1; }
grep -q 'finger bit at' "$tmp/gh.txt"                                 || { echo "FAIL: polls"; exit 1; }
grep -q '800 lines' "$tmp/gh.txt"                                     || { echo "FAIL: swipe decrypt"; exit 1; }
grep -A2 '^  baseline G' "$tmp/gh.txt" | grep -q 'ratio 0.79'         || { echo "FAIL: G vs H baseline"; exit 1; }
python3 "$tools/compare_probe_dumps.py" "$tmp"/dump/dump-G-*.json > "$tmp/gg.txt"
grep 'G vs G' "$tmp/gg.txt" | grep -q reads && { echo "FAIL: G vs G compares 2 variants"; exit 1; }
grep -q 'dumps: G x2' "$tmp/gg.txt"                                   || { echo "FAIL: G x2"; exit 1; }
echo "OK: probe dump + comparison"
