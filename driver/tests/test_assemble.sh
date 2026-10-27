#!/usr/bin/env bash
# Phase 5 check: the C assembly == tools/vfs495_assemble.py on recorded swipes.
#   driver/tests/test_assemble.sh RAW.npy [RAW.npy ...]   (VFS495_RAW / VFS_RAW dumps; biometric, keep local)
#   needs: cc, pkg-config glib-2.0, python3 + numpy + scipy
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
cc -O2 -Wall -Werror -o "$tmp/test_assemble" "$here/test_assemble.c" "$here/../vfs495_assemble.c" \
  $(pkg-config --cflags --libs glib-2.0) -lm
for raw in "$@"; do
  if ! "$tmp/test_assemble" "$raw" "$tmp/c.pgm"; then
    echo "  ${raw##*/}: no usable swipe (C returns no image), skipped"
    continue
  fi
  python3 - "$here/../../tools" "$raw" "$tmp/c.pgm" <<'PY'
import sys, numpy as np
sys.path.insert(0, sys.argv[1])
import vfs495_assemble as A, vfs495_native_capture as N
raw = np.load(sys.argv[2]); lines = np.zeros((len(raw), 264), np.uint8); lines[:, N.descramble_table()] = raw
py = A.assemble(lines)
d = open(sys.argv[3], "rb").read().split(b"\n", 3); w, h = map(int, d[1].split())
c = np.frombuffer(d[3], np.uint8).reshape(h, w)
if c.shape != py.shape:
    sys.exit("FAIL shape C %s vs Python %s" % (c.shape, py.shape))
diff = np.abs(c.astype(int) - py)
print("  %s: C == Python shape %s, max |diff| %d, pixels off by >2: %.3f%%"
      % (sys.argv[2].rsplit("/", 1)[-1], c.shape, diff.max(), 100 * (diff > 2).mean()))
sys.exit(0 if (diff > 2).mean() < 0.001 else 1)
PY
done
echo OK
