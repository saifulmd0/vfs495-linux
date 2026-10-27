# NixOS module for the Validity VFS495 (138a:003f) fingerprint reader.
#
#   imports = [ /path/to/vfs495-linux/nixos/module.nix ];
#   services.vfs495.enable = true;                  # backend = "native" (default) or "bridge"
#   security.pam.services.sudo.fprintAuth = true;   # etc., as for any fprintd reader
#
# Both backends need the per-device setup data, recorded once from one run of HP's binary:
#   sudo vfs495-setup        (installed by this module; writes setupFile and capturesDir, deletes HP's files)
#   native: uses setupFile. If only capturesDir exists (older recordings), vfs495-setup-bin.service packs it.
#   bridge: uses capturesDir (init_cmds.json + capture_cmds.json).
# None of that data is copied into the Nix store (it is per-device and HP's).
{ config, lib, pkgs, ... }:

let
  cfg = config.services.vfs495;
  defaultSetup = "/var/lib/vfs495/setup.bin";

  libfprint-vfs495 = pkgs.callPackage ../driver { };
  # the one-time setup tool, preset to this module's paths
  vfs495-setup = pkgs.writeShellScriptBin "vfs495-setup" ''
    export VFS495_SETUP=''${VFS495_SETUP:-${cfg.setupFile}}
    export VFS495_CAPTURES=''${VFS495_CAPTURES:-${cfg.capturesDir}}
    exec ${pkgs.callPackage ../runtime { }}/bin/vfs495-setup "$@"
  '';
  python = pkgs.python3.withPackages (ps: with ps; [ numpy scipy pyusb cryptography ]);
  # only what the services run (never captures/: per-device data stays out of the store)
  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      (lib.fileset.fileFilter (f: f.hasExt "py") ../tools)
      ../driver/vfs495_descramble.inc
      ../packaging/vfs495-fprint/usr/lib/vfs495-fprint/bridge.py
    ];
  };
  tools = "${src}/tools";
  bridge = "${src}/packaging/vfs495-fprint/usr/lib/vfs495-fprint/bridge.py";
in
{
  options.services.vfs495 = {
    enable = lib.mkEnableOption "fingerprint login with the Validity VFS495 (138a:003f) swipe reader";

    backend = lib.mkOption {
      type = lib.types.enum [ "native" "bridge" ];
      default = "native";
      description = ''
        native: fprintd uses libfprint patched with the vfs495 driver (driver/).
        bridge: fallback. Stock libfprint's virtual_image device, fed by a root service that captures
        with tools/vfs495_native_capture.py (Python, no HP binary at runtime).
        Templates are not interchangeable: re-enroll after switching.
      '';
    };

    setupFile = lib.mkOption {
      type = lib.types.str;
      default = defaultSetup;
      description = "The native driver's setup file (tools/make_setup_bin.py). Keep it root-only (0600).";
    };

    capturesDir = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/vfs495-fprint/captures";
      description = "Directory with init_cmds.json + capture_cmds.json from the one-time HP trace.";
    };

    debug = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Log driver debug output and the matcher's scores in fprintd's journal.";
    };
  };

  config = lib.mkIf cfg.enable (lib.mkMerge [
    {
      services.fprintd.enable = true;
      environment.systemPackages = [ vfs495-setup ];
      systemd.tmpfiles.rules = [
        "d /var/lib/vfs495 0700 root root -"
        "d /var/lib/vfs495-fprint 0700 root root -"
      ];
    }

    (lib.mkIf (cfg.backend == "native") {
      services.fprintd.package = pkgs.fprintd.override { libfprint = libfprint-vfs495; };

      systemd.services.vfs495-setup-bin = {
        description = "VFS495: pack ${cfg.setupFile} from the recorded setup commands";
        unitConfig = {
          ConditionPathExists = [ "!${cfg.setupFile}" "${cfg.capturesDir}/init_cmds.json" "${cfg.capturesDir}/capture_cmds.json" ];
        };
        before = [ "fprintd.service" ];
        wantedBy = [ "multi-user.target" ];
        serviceConfig = {
          Type = "oneshot";
          UMask = "0077";
          ExecStart = "${python}/bin/python3 ${tools}/make_setup_bin.py ${cfg.capturesDir} ${cfg.setupFile}";
        };
      };

      systemd.services.fprintd = {
        after = [ "vfs495-setup-bin.service" ];
        environment = lib.mkMerge [
          (lib.mkIf (cfg.setupFile != defaultSetup) { VFS495_SETUP = cfg.setupFile; })
          (lib.mkIf cfg.debug { G_MESSAGES_DEBUG = "libfprint-vfs495 libfprint-print"; })
        ];
      };
    })

    (lib.mkIf (cfg.backend == "bridge") {
      systemd.services.fprintd = {
        environment = {
          FP_VIRTUAL_IMAGE = "/run/fprint/virtimg_sock";
        } // lib.optionalAttrs cfg.debug { G_MESSAGES_DEBUG = "libfprint-print"; };
        serviceConfig.RuntimeDirectory = "fprint";
      };

      systemd.services.vfs495-bridge = {
        description = "VFS495 fingerprint capture bridge (feeds fprintd's virtual_image device)";
        after = [ "fprintd.service" ];
        wantedBy = [ "multi-user.target" ];
        unitConfig.ConditionPathExists = [ "${cfg.capturesDir}/init_cmds.json" "${cfg.capturesDir}/capture_cmds.json" ];
        environment = {
          FP_VIRTUAL_IMAGE = "/run/fprint/virtimg_sock";
          VFS495_CAPTURE = "${tools}/vfs495_native_capture.py";
          VFS495_CAPTURES = cfg.capturesDir;
        };
        serviceConfig = {
          ExecStart = "${python}/bin/python3 ${bridge}";
          Restart = "always";
          RestartSec = 2;
          UMask = "0077";
        };
      };
    })
  ]);
}
