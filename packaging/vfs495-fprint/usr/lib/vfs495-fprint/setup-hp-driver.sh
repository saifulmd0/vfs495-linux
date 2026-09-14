#!/bin/bash
# Download HP's Validity Linux driver (SoftPaq sp84530) from HP, extract the sensor
# binary, apply the 5-byte diagnostic-gate patch, and install to /var/lib/vfs495-fprint.
# HP's binary is proprietary and NOT redistributed in this package; it is fetched
# from HP's own server here (like firmware-installer packages do).
set -euo pipefail
DEST=/var/lib/vfs495-fprint
LIB=/usr/lib/vfs495-fprint
URL=https://ftp.hp.com/pub/softpaq/sp84501-85000/sp84530.tar
MD5=9877c69c4f4b57a00f9e4afbcd9baacc
mkdir -p "$DEST/lib"
if [ -x "$DEST/validity-sensor-unlocked" ] && [ -f "$DEST/lib/libssl.so.0.9.8" ]; then
  echo "vfs495: HP driver already installed."; exit 0
fi
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT; cd "$TMP"
if [ -n "${VFS495_HP_TAR:-}" ] && [ -f "$VFS495_HP_TAR" ]; then
  cp "$VFS495_HP_TAR" sp84530.tar
else
  echo "vfs495: downloading HP driver package from HP (sp84530, ~3 MB)..."
  curl -fsSL -o sp84530.tar "$URL" || wget -qO sp84530.tar "$URL"
fi
echo "$MD5  sp84530.tar" | md5sum -c - >/dev/null || { echo "vfs495: checksum mismatch, aborting"; exit 1; }
tar xf sp84530.tar
mkdir rpm && cd rpm
7z x -y ../SP84530/Validity-Sensor-Setup-4.5-136.0.x86_64.rpm >/dev/null
7z x -y ./*.cpio >/dev/null
BIN=usr/sbin/validity-sensor
[ -f "$BIN" ] || { echo "vfs495: validity-sensor not found in package"; exit 1; }
# 5-byte patch: bypass main() gate at VA 0x44122d (jmp 0x4412b4) so diagnostic cmds run
python3 - "$BIN" "$DEST/validity-sensor-unlocked" <<'PY'
import sys
src,dst=sys.argv[1],sys.argv[2]; d=bytearray(open(src,"rb").read()); off=0x44122d-0x400000
assert d[off:off+4]==bytes.fromhex("488b7b08"), "unexpected binary (need Validity 4.5-136)"
d[off:off+5]=b"\xe9"+(0x4412b4-(0x44122d+5)).to_bytes(4,"little",signed=True)
open(dst,"wb").write(d)
PY
chmod 755 "$DEST/validity-sensor-unlocked"
cp usr/sbin/HPUsbVFS495.img "$DEST/" 2>/dev/null || true
# OpenSSL-0.9.8 stubs (binary links them but never calls them; crypto is static)
cp "$LIB/lib/libssl.so.0.9.8" "$DEST/lib/"
cp "$LIB/lib/libcrypto.so.0.9.8" "$DEST/lib/"
echo "vfs495: HP driver installed to $DEST"
