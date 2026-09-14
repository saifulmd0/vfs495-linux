#!/bin/bash
# Build vfs495-fprint_<ver>_amd64.deb. Requires: gcc, dpkg-deb.
set -e; cd "$(dirname "$0")"
L=vfs495-fprint/usr/lib/vfs495-fprint; mkdir -p $L/lib
gcc -shared -fPIC -Wl,-soname,libssl.so.0.9.8    -o $L/lib/libssl.so.0.9.8    $L/stub.c
gcc -shared -fPIC -Wl,-soname,libcrypto.so.0.9.8 -o $L/lib/libcrypto.so.0.9.8 $L/stub.c
VER=$(sed -n 's/^Version: //p' vfs495-fprint/DEBIAN/control)
dpkg-deb --build --root-owner-group vfs495-fprint "vfs495-fprint_${VER}_amd64.deb"
echo "built vfs495-fprint_${VER}_amd64.deb"
