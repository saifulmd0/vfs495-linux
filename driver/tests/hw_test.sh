#!/usr/bin/env bash
# Run driver/tests/hw_test.py against the sensor with the patched libfprint built from this tree.
#   driver/tests/hw_test.sh capture 10 /tmp/swipes     (asks for sudo: USB access)
#   VFS495_RAW=DIR G_MESSAGES_DEBUG=libfprint-vfs495 driver/tests/hw_test.sh ...
# Setup file: $VFS495_SETUP if set, else one packed from the repo's captures/ (tools/make_setup_bin.py)
# into a private temp dir, removed afterwards; VFS495_SETUP_MINIMAL=1 packs it with --minimal (only HP's two
# init patches, docs/FINDINGS.md "T7 run 10"). Needs Nix (flakes for builtins.getFlake).
# Stop fprintd first if it holds the sensor.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
pkgs='(builtins.getFlake "nixpkgs").legacyPackages.${builtins.currentSystem}'
lib=$(nix build --no-link --print-out-paths --impure --expr "$pkgs.callPackage $here/.. { }" | grep -v -- '-dev$\|-devdoc$' | head -1)
env=$(nix build --no-link --print-out-paths --impure --expr "let p = $pkgs; in p.buildEnv {
  name = \"vfs495-hwtest\";
  paths = [ (p.python3.withPackages (ps: [ ps.pygobject3 ])) p.gusb.out p.json-glib.out p.glib.out p.gobject-introspection ];
  pathsToLink = [ \"/bin\" \"/lib\" ];
}")

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
chmod 700 "$tmp"
if [ -z "${VFS495_SETUP:-}" ]; then
  VFS495_SETUP=$tmp/setup.bin
  "$env/bin/python3" "$here/../../tools/make_setup_bin.py" ${VFS495_SETUP_MINIMAL:+--minimal} \
    "$here/../../captures" "$VFS495_SETUP"
fi

run=()
[ "$(id -u)" = 0 ] || [ -n "${VFS495_TEST_NOSUDO:-}" ] || run=(sudo)
"${run[@]}" env \
  GI_TYPELIB_PATH="$lib/lib/girepository-1.0:$env/lib/girepository-1.0" \
  LD_LIBRARY_PATH="$lib/lib" \
  VFS495_SETUP="$VFS495_SETUP" \
  ${VFS495_RAW:+VFS495_RAW="$VFS495_RAW"} \
  ${G_MESSAGES_DEBUG:+G_MESSAGES_DEBUG="$G_MESSAGES_DEBUG"} \
  ${VFS495_TEST_DRIVER:+VFS495_TEST_DRIVER="$VFS495_TEST_DRIVER"} \
  ${FP_VIRTUAL_IMAGE:+FP_VIRTUAL_IMAGE="$FP_VIRTUAL_IMAGE"} \
  "$env/bin/python3" "$here/hw_test.py" "$@"
