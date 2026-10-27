#!/usr/bin/env bash
# Phase 3 offline check: the C session layer == tools/ssl_session.py, byte for byte.
#   driver/tests/test_ssl.sh       (needs: cc, pkg-config glib-2.0 gio-2.0 openssl, python3 + pyusb + cryptography)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
python3 "$here/ssl_vectors.py" "$tmp/v.ini"
cc -Wall -Werror -o "$tmp/test_ssl" "$here/test_ssl.c" "$here/../vfs495_ssl.c" \
  $(pkg-config --cflags --libs glib-2.0 gio-2.0 openssl)
"$tmp/test_ssl" "$tmp/v.ini"
