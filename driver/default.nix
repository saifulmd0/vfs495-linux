# libfprint with the vfs495 driver added (out-of-tree patch, see PLAN.md).
#
# Dev build (any nixpkgs with libfprint 1.94.x):
#   nix build --impure --expr '(builtins.getFlake "nixpkgs").legacyPackages.x86_64-linux.callPackage ./driver { }'
# NixOS: services.fprintd.package = pkgs.fprintd.override { libfprint = pkgs.callPackage ./driver { }; };
{ lib, libfprint }:
let
  files = [ "vfs495.c" "vfs495_proto.h" "vfs495_descramble.inc" "vfs495_setup.c" "vfs495_setup.h"
            "vfs495_ssl.c" "vfs495_ssl.h" "vfs495_assemble.c" "vfs495_assemble.h" ];
  # only the sources: editing docs or tests must not rebuild libfprint
  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions (map (f: ./. + "/${f}") files);
  };
in
libfprint.overrideAttrs (old: {
  pname = "libfprint-vfs495";

  postPatch = (old.postPatch or "") + ''
    mkdir -p libfprint/drivers/vfs495
    cp ${lib.concatMapStringsSep " " (f: "${src}/${f}") files} libfprint/drivers/vfs495/

    # register the driver: sources, and AES/SHA/MD5/RSA through libfprint's openssl helper
    substituteInPlace libfprint/meson.build \
      --replace-fail "    'vfs5011' : files('drivers/vfs5011.c')," \
                     "    'vfs5011' : files('drivers/vfs5011.c'),
    'vfs495' : files('drivers/vfs495/vfs495.c', 'drivers/vfs495/vfs495_setup.c', 'drivers/vfs495/vfs495_ssl.c', 'drivers/vfs495/vfs495_assemble.c'),"
    substituteInPlace meson.build \
      --replace-fail "    'vfs5011': { 'endian_dependent': true }," \
                     "    'vfs5011': { 'endian_dependent': true },
    'vfs495': { 'helper': ['openssl'] },"

    # 138a:003f is on libfprint's "known unsupported" list; it is supported now
    substituteInPlace libfprint/fprint-list-udev-hwdb.c \
      --replace-fail "  { .vid = 0x138a, .pid = 0x003f }," ""
    # ...and the committed udev hwdb the tests compare against (= meson compile sync-udev-hwdb)
    substituteInPlace data/autosuspend.hwdb \
      --replace-fail "usb:v138Ap003F*
" ""
    substituteInPlace data/autosuspend.hwdb \
      --replace-fail "# Supported by libfprint driver vfs5011
" "# Supported by libfprint driver vfs495
usb:v138Ap003F*
 ID_AUTOSUSPEND=1
 ID_PERSIST=0

# Supported by libfprint driver vfs5011
"
  '';
})
