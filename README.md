# VFS495 fingerprint reader on Linux (Validity `138a:003f`)

**Working Linux fingerprint login for the Validity Sensors VFS495 (USB `138a:003f`)** — a
swipe reader found in many 2013–2015 HP EliteBook / ProBook / ZBook laptops that
[libfprint does not support](https://fprint.freedesktop.org/supported-devices.html).

This project reverse‑engineers the sensor and provides two paths into **fprintd + PAM** (`sudo`,
login screen, lock screen):

- **Native libfprint driver** (`driver/`): talks to the sensor directly. No HP binary, no `gdb` at
  runtime. It replays the sensor's per-device setup data, recorded once from your own sensor.
- **Bridge** (the packaged `.deb`): HP's proprietary binary under `gdb` feeds libfprint's
  `virtual_image` device. It still works and is the fallback.

> Status: the **native driver works on hardware** (HP EliteBook, NixOS, libfprint 1.94.100):
> secure session, capture, swipe assembly, enroll and verify through libfprint. Same-finger swipes
> score a mean of 71.7 against each other (threshold 40). Too-fast swipes are rejected with a retry.
> The one-time setup (`vfs495-setup`) records the sensor's setup data from one run of HP's driver.
> Not yet done: the end-to-end fprintd/PAM test on the native path and a Debian package of the native
> driver. The `.deb` below is still the bridge. The bridge path is
> verified end to end on Debian 13 (`fprintd-verify`, `sudo`, login).

Keywords: VFS495, 138a:003f, Validity Sensors, Synaptics Falcon, fingerprint, Linux, fprintd,
libfprint, PAM, HP EliteBook / ProBook / ZBook.

---

## Does this fit my hardware?

Run `lsusb`. If you see:

```
Bus ... Device ...: ID 138a:003f Validity Sensors, Inc. VFS495 Fingerprint Reader
```

then yes. This is the **Falcon**‑generation Validity swipe sensor (older than the 0090/0097
"Prometheus" area sensors handled by [python‑validity](https://github.com/uunicorn/python-validity)).

## What works

- ✅ The secure session (Validity's SSLv3 variant), opened by the host. No pairing gate, see
  [`docs/SSL_PROTOCOL.md`](docs/SSL_PROTOCOL.md).
- ✅ Capture: finger detection, the AES-256 encrypted swipe stream, decryption and descrambling.
- ✅ Swipe assembly modelled on HP's (`IRreconstructImage`), in C, pixel-identical to the Python
  reference (`tools/vfs495_assemble.py`).
- ✅ Native libfprint driver: enroll and verify on hardware. Fast swipes return `TOO_FAST`, short
  ones `TOO_SHORT`.
- ✅ Bridge path: enroll and verify through `fprintd`, PAM login / sudo (the `.deb`).
- ⚠️ The sensor runs HP's firmware patches (~5 KB), authenticated per sensor. They can't be shipped
  or generated, so each user records them once from their own sensor with one traced HP run.

## Quick start (the easy way — one package)

Download the latest `vfs495-fprint_*_amd64.deb` from the
[Releases page](https://github.com/saifulmd0/vfs495-linux/releases), then:
```bash
sudo apt install ./vfs495-fprint_*_amd64.deb   # pulls deps, downloads HP's driver from HP, sets up fprintd+PAM
fprintd-enroll                                  # swipe the same finger slowly, full length, when prompted
sudo -k && sudo true                            # test: swipe → fingerprint login works (password still works)
```
That's it — no tinkering. The package fetches HP's proprietary driver from HP's own server at install
time (it is not redistributed), configures the capture service, fprintd, udev and PAM.
Build it yourself: `packaging/build-deb.sh`.

## Quick start (native driver, NixOS)

In your configuration:
```nix
imports = [ /path/to/vfs495-linux/nixos/module.nix ];
services.vfs495.enable = true;          # backend = "native" (default) or "bridge"
security.pam.services.sudo.fprintAuth = true;
```
Then record your sensor's setup data once and enroll:
```bash
sudo vfs495-setup     # runs HP's driver once (~10 s, no swipe), writes /var/lib/vfs495/setup.bin, deletes HP's files
fprintd-enroll
```
Details: [`docs/SETUP_FPRINTD.md`](docs/SETUP_FPRINTD.md#native-driver).
Driver test without fprintd: `driver/tests/hw_test.sh capture 5 /tmp/swipes`.

## Quick start (manual / development)

You need HP's Validity Linux driver package (proprietary; **not** redistributed here) — see
[`runtime/README.md`](runtime/README.md) for the one‑time harness setup (download from HP, extract,
build the small shims, apply the 5‑byte gate patch). Then:

```bash
# one-time: set up the capture harness (see runtime/README.md)
# then verify a capture works:
sudo VFS495_HOME=$PWD python3 tools/vfs495_capture_asm.py /tmp/fp.pgm   # swipe your finger

# fingerprint login via fprintd + PAM:
#   full guided steps in docs/SETUP_FPRINTD.md
sudo apt install fprintd libpam-fprintd python3-usb python3-numpy python3-scipy python3-pil
# ...configure fprintd socket + run the bridge + fprintd-enroll + pam-auth-update...
```

Full login setup: **[`docs/SETUP_FPRINTD.md`](docs/SETUP_FPRINTD.md)**.

## How it works

**Native driver** (`driver/`, a patch on libfprint 1.94.x):
```
fprintd ─▶ libfprint vfs495 driver
             │ open:   init sequence + HP's firmware patches (replayed from /var/lib/vfs495/setup.bin)
             │         ─▶ SSLv3 session, RSA key from the sensor's own flash
             │ swipe:  setup commands with a fresh random image key ─▶ poll for a finger
             │         ─▶ AES-256-CBC swipe stream ─▶ 264-column lines, descrambled
             │         ─▶ assembly (worker thread): lag between the two sensor rows = finger speed
             ▼
           200×≤300 image ─▶ NBIS minutiae + bozorth3 ─▶ enroll / verify ─▶ PAM
```
`setup.bin` holds the sensor's init and setup commands, captured once from one traced run of HP's
binary on your own sensor. It's per-device data: it stays in `/var/lib/vfs495` (root, 0600) and is
never redistributed. See [`driver/README.md`](driver/README.md) and [`driver/PLAN.md`](driver/PLAN.md).

**Bridge** (the `.deb`):
```
validity-sensor (HP, under gdb) ─▶ assembled image ─▶ vfs495-bridge ─▶ FP_VIRTUAL_IMAGE socket
  ─▶ fprintd's virtual_image device ─▶ enroll / verify ─▶ PAM
```

- The **descramble table** (`driver/vfs495_descramble.inc`): the sensor reads its columns out of
  order; this permutation puts them back. Extracted from the running driver; regenerate with
  `runtime/dump_perm.gdb`.
- The **assembly**: the sensor has a 200-pixel main row and a 64-pixel second row. The delay before
  a ridge seen by one row shows up in the other gives the finger speed, and that sets how many
  lines make one image row. Details in [`docs/FINDINGS.md`](docs/FINDINGS.md).

## Repository layout

| Path | What |
|------|------|
| `driver/` | The **native libfprint driver** (`vfs495*.c`), its Nix build (`default.nix`), tests, `PLAN.md`. |
| `nixos/` | NixOS module: `services.vfs495.enable`, `backend = "native"` or `"bridge"`. |
| `tools/` | Python reference implementation (session, native capture, assembly), `make_setup_bin.py`, the bridge. |
| `runtime/` | The `gdb` harness, `LD_PRELOAD` USB logger, and how to stand up HP's binaries (for the one-time setup trace). |
| `packaging/` | The Debian package (bridge path). |
| `ghidra/` | Ghidra script to reproduce the decompilation/analysis. |
| `docs/` | `FINDINGS.md` (RE log), `BINARY_RE.md` (full-binary RE reference), `SSL_PROTOCOL.md`, `WRAPPER.md`, `SETUP_FPRINTD.md`. |

## Troubleshooting

- **Swipe timing.** On the **native** driver the sensor arms in well under a second. On the **bridge**
  it needs about 2 seconds (HP's binary is started and initialises the secure session). When a prompt
  appears (login, `sudo`, `fprintd-enroll`), **wait a moment, then swipe slowly**, whole fingertip, one
  steady motion. A swipe made instantly after the prompt is usually missed; just swipe again — the
  capture retries. (Native open latency is tunable: `VFS495_INIT_PAUSE_MS`, see `driver/README.md`.)
- **See what happened.** `sudo journalctl -u vfs495-bridge -f` shows *finger needed → swipe now*,
  *delivered scan*, or *no finger captured*. `sudo journalctl -u fprintd | grep score` shows the
  matcher's score for every swipe (**≥ 40 = match**).
- **Check your enrollment quality.** `sudo vfs495-match --capture 3` takes three swipes and prints
  the scores of each against your enrolled finger and against each other. Same finger should score
  40–150; if your swipes score well against each other but poorly against the enrolled template,
  re-enroll from exactly those swipes: `sudo vfs495-match --enroll /run/vfs495-fprint/test/swipe-*.pgm`
  (or `fprintd-delete $USER && fprintd-enroll` for five fresh slow swipes). Enroll from a
  terminal; the GNOME Settings dialog and a running verify can't share the device.
- **The sensor can get stuck** after many rapid captures: it returns a few lines immediately
  instead of waiting for a finger, so every swipe is "tiny scan" / "not captured" and
  `vfs495-match --capture` reports e.g. `200x15`. Only a **full power-off** clears it (shut
  down, wait 10 s, power on). A warm reboot, USB re-enumeration and a USB port power cycle do
  not — the sensor keeps its state while the board stays powered.
- Password authentication always remains as a PAM fallback — you cannot be locked out.

## Limitations

- **One-time setup needs HP's binary.** The sensor needs HP's firmware patches even for its encrypted
  session (tested: the bare ROM refuses it). The patches are authenticated per sensor, so each
  user records them once from their own sensor with `vfs495-setup` (one run of HP's driver, ~10 s), and
  the driver replays them after that. This project doesn't forge or reproduce that authentication.
  Tested on one sensor so far; reports from a second VFS495 are welcome.
- **Out of tree.** The driver is a patch on libfprint (Nix: `driver/default.nix`), not upstream.
- **Re-enroll when switching paths.** Templates from the bridge (HP-assembled images) don't match
  native captures, and the other way round.
- **Bridge path:** HP's binary under `gdb` as root. Event-driven, so idle when nobody authenticates.
- **Stuck sensor** (see Troubleshooting): seen on the bridge path; not yet seen on the native path.

## Roadmap

1. Native driver in packages: Debian (patched `libfprint-2`), with the bridge as a fallback.
2. End-to-end tests on the native path: fprintd, `sudo`, GDM login, lock screen, suspend/resume; a second sensor.
3. Distribute out of tree like python-validity (the NixOS module / a COPR- or PPA-style package), keeping the
   clean-room driver to libfprint standards as an upstream-insurance path — see
   [`driver/README.md`](driver/README.md#distribution--upstreaming).
4. Optional: synthesize the ~31 KB of near-constant config so only the firmware patches are captured; close the
   matching-score gap to HP. The binary itself is now fully reverse-engineered
   ([`docs/BINARY_RE.md`](docs/BINARY_RE.md)); reproducing HP's per-sensor patch authentication stays out of scope.

## Legal & privacy

- **No proprietary HP/Validity/Synaptics binaries or decompiled source are included.** You download
  HP's package yourself (`runtime/README.md`). This repo contains only original tools, notes, and
  reproduction scripts.
- **No fingerprint images / biometric data / per‑device keys are included.** Everything device‑specific
  (RSA key, descramble table if it differs, images) is generated locally on your machine.
- Reverse‑engineering your own hardware for interoperability is broadly permitted; you are
  responsible for your use. Provided **as‑is, no warranty** (see `LICENSE`).

## Credits / prior art

- [nmikhailov/Validity90](https://github.com/nmikhailov/Validity90) &
  [uunicorn/python-validity](https://github.com/uunicorn/python-validity) — newer Validity/Synaptics
  sensors; the pairing insight came from here.
- The earlier VFS495 community drivers (rindeal, sq4, zvoznikau, ryantrinkle — from Balint Banyasz's
  work) that wrap the proprietary daemon.
- libfprint / fprintd (freedesktop).

Built with a lot of `gdb`. PRs are very welcome, especially testing on a second VFS495.
