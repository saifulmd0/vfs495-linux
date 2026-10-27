#!/usr/bin/env bash
# Phase 2 check: the C parser reads exactly the commands the Python client uses.
#   driver/tests/test_setup.sh [CAPTURES_DIR]      (needs: cc, pkg-config glib-2.0, python3)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
cap=${1:-$here/../../captures}
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
cc -Wall -Werror -o "$tmp/test_setup" "$here/test_setup.c" "$here/../vfs495_setup.c" $(pkg-config --cflags --libs glib-2.0)
# reference dump in Python. --minimal: the commands probe_patches.py's step M sent (an independent implementation).
# The arming command is the last 02 config; its key sits in the first 48 B of its type-6 TLV (2927 in HP's 3033 B one).
for mode in full minimal; do
  python3 "$here/../../tools/make_setup_bin.py" $([ $mode = minimal ] && echo --minimal) "$cap" "$tmp/setup.bin" >/dev/null
  "$tmp/test_setup" "$tmp/setup.bin" --corrupt > "$tmp/c.txt"
  VFS495_CAPTURES="$cap" python3 - "$here/../../tools" $mode > "$tmp/py.txt" <<'PY'
import hashlib, json, os, struct, sys
sys.path.insert(0, sys.argv[1])
cap = os.environ["VFS495_CAPTURES"]
init = [bytes.fromhex(h) for h in json.load(open(cap + "/init_cmds.json"))]
setup = [(bytes.fromhex(h), r) for h, r in json.load(open(cap + "/capture_cmds.json"))]
if sys.argv[2] == "minimal":
    import probe_patches
    _, setup = probe_patches.variant_cmds(init, setup, "M")
arm = max(i for i, (c, _) in enumerate(setup) if c[:1] == b"\x02")
def key_off(c):
    o = 5
    while o < len(c):
        t, n = struct.unpack_from("<HH", c, o)
        if t == 6:
            return o + 4
        o += 4 + n
if sys.argv[2] == "full":
    assert len(setup[arm][0]) == 3033 and key_off(setup[arm][0]) == 2927
for i, c in enumerate(init):
    print("init", i, len(c), hashlib.sha256(c).hexdigest())
for i, (c, reads) in enumerate(setup):
    print("setup", i, int(i == arm), len(c), hashlib.sha256(c).hexdigest(), *reads,
          *(["key=%d" % key_off(c)] if i == arm else []))
PY
  diff -u "$tmp/py.txt" "$tmp/c.txt"
  echo "OK ($mode): C parser == Python ($(grep -c ^init "$tmp/c.txt") init, $(grep -c ^setup "$tmp/c.txt") setup commands, $(grep -o 'key=[0-9]*' "$tmp/c.txt"))"
done
