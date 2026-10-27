# vfs495-setup with everything it needs (gdb, 7z, gcc, libusb-0.1, python with cryptography + pyusb).
#   nix build --impure --expr '(builtins.getFlake "nixpkgs").legacyPackages.x86_64-linux.callPackage ./runtime { }'
#   sudo ./result/bin/vfs495-setup
{ lib, stdenvNoCC, makeWrapper, gdb, p7zip, gcc, python3, libusb-compat-0_1, curl, coreutils, gnutar, gnugrep
, gnused, procps, glibc, libusb1 }:

let
  python = python3.withPackages (ps: with ps; [ cryptography pyusb ]);
  # only what the tool runs: never captures/ (per-device data)
  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ./vfs495-setup ./dump_keyblock.py ./trace_to_init.py ./usblog.c
      ../tools/ssl_session.py ../tools/make_setup_bin.py
    ];
  };
in
stdenvNoCC.mkDerivation {
  pname = "vfs495-setup";
  version = "0.1";
  inherit src;
  nativeBuildInputs = [ makeWrapper ];
  installPhase = ''
    mkdir -p $out/share/vfs495 $out/bin
    cp -r runtime tools $out/share/vfs495/
    makeWrapper $out/share/vfs495/runtime/vfs495-setup $out/bin/vfs495-setup \
      --prefix PATH : ${lib.makeBinPath [ gdb p7zip gcc python curl coreutils gnutar gnugrep gnused procps glibc.bin ]} \
      --set-default VFS495_LIBUSB0 ${libusb-compat-0_1.out}/lib:${libusb1.out}/lib
  '';
  meta.mainProgram = "vfs495-setup";
}
