# Capture harness (runtime/)

The capture path drives HP's proprietary `validity-sensor` binary (which establishes the sensor's
secure session and performs the scan) under `gdb`, and harvests the descrambled / assembled image
from its memory. **HP's binaries are NOT included here** — download them yourself (one-time), then
build the small shim libraries below.

## 1. Get HP's Validity Linux driver (proprietary; free download from HP)
SoftPaq **sp84530** ("Validity Fingerprint Reader Driver for SuSE Linux SLED 11", Validity 4.5-136):
```bash
cd /tmp
curl -O https://ftp.hp.com/pub/softpaq/sp84501-85000/sp84530.tar
tar xf sp84530.tar
# extract the RPM payload:
mkdir vsx && cd vsx
7z x -y ../SP84530/Validity-Sensor-Setup-4.5-136.0.x86_64.rpm >/dev/null
7z x -y *.cpio >/dev/null
# you now have: usr/sbin/validity-sensor, usr/lib64/libvfsFprintWrapper.so, usr/bin/vcsFPService, HPUsbVFS*.img
```
Copy `usr/sbin/validity-sensor` somewhere and note its path.

## 2. Make the "unlocked" binary
HP shipped `validity-sensor` with its diagnostic commands gated off in `main()`. A 5-byte patch
re-enables them (does not change any sensor behaviour). At the byte for virtual address `0x44122d`,
replace `48 8b 7b 08` with `e9 82 00 00 00` (an unconditional `jmp 0x4412b4`):
```bash
python3 - <<'PY'
p="validity-sensor"; d=bytearray(open(p,"rb").read())
off=0x44122d-0x400000
assert d[off:off+4]==bytes.fromhex("488b7b08")
d[off:off+5]=b"\xe9"+ (0x4412b4-(0x44122d+5)).to_bytes(4,"little",signed=True)
open("bin/validity-sensor-unlocked","wb").write(d)
print("patched -> bin/validity-sensor-unlocked")
PY
```
Put the result at `runtime/bin/validity-sensor-unlocked`.

## 3. Build the shim libraries
`validity-sensor` links `libssl.so.0.9.8` / `libcrypto.so.0.9.8` (OpenSSL 0.9.8) but does its crypto
statically, so empty stubs satisfy the loader. `libusb-0.1` comes from your distro.
```bash
cd runtime && mkdir -p lib bin
gcc -shared -fPIC -Wl,-soname,libssl.so.0.9.8    -o lib/libssl.so.0.9.8    stub.c
gcc -shared -fPIC -Wl,-soname,libcrypto.so.0.9.8 -o lib/libcrypto.so.0.9.8 stub.c
gcc -shared -fPIC -O2 -o lib/usblog.so usblog.c -ldl            # optional USB traffic logger
apt-get download libusb-0.1-4 && dpkg-deb -x libusb-0.1-4_*.deb d && \
  cp -a d/usr/lib/*/libusb-0.1.so.4* lib/ 2>/dev/null || cp -a d/lib/*/libusb-0.1.so.4* lib/
```
(`stub.c` is `void __vfs_stub(void){}` — provided here.)

## 4. Test
```bash
sudo VFS495_HOME=$PWD/.. LD_LIBRARY_PATH=$PWD/lib bin/validity-sensor-unlocked getver   # sensor version
sudo VFS495_HOME=$PWD/.. python3 ../tools/vfs495_capture_asm.py /tmp/fp.pgm             # swipe -> image
```

## Files
- `harvest_assembled.py` — gdb: harvest the motion-compensated assembled image (the match-quality one).
- `harvest_lines.py` — gdb: harvest raw descrambled scan lines (for the reconstruct.py path).
- `dump_*.py`, `dump_perm.gdb` — gdb dumpers used during RE (descramble table, RSA key, SSL KDF/record vectors).
- `usblog.c` — `LD_PRELOAD` shim logging all libusb-0.1 bulk I/O.
- `vs.sh` — allowlisted wrapper around the unlocked binary (refuses the dangerous provisioning/OTP/flash cmds).

Regenerate the descramble table for your sensor with `dump_perm.gdb` if the bundled
`driver/vfs495_descramble.inc` ever mismatches (it should be identical for all VFS495).
