# VFS495 fingerprint reader on Linux (Validity `138a:003f`)

**Working Linux fingerprint login for the Validity Sensors VFS495 (USB `138a:003f`)** — a
swipe reader found in many 2013–2015 HP EliteBook / ProBook / ZBook laptops that
[libfprint does not support](https://fprint.freedesktop.org/supported-devices.html).

This project reverse‑engineers the sensor and provides a **working end‑to‑end path**: capture →
image assembly → enrollment → verification, wired into **fprintd + PAM** so you can unlock
`sudo`, the login screen, and the lock screen with your fingerprint.

> Status: **working proof‑of‑concept.** Genuine finger vs. impostor match scores 79 vs 5
> (threshold 40). It is *not yet a native libfprint driver* — capture currently drives HP's
> proprietary userspace binary under `gdb` (see [Limitations](#limitations)). A native driver is
> the roadmap. Contributions welcome.

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

- ✅ Talk to the sensor, upload its firmware "patches", drive a capture.
- ✅ Decode + **descramble** the raw scan lines into a real image.
- ✅ Get **match‑quality** assembled fingerprints (motion‑compensated).
- ✅ **Enroll & verify** through `fprintd`; **PAM login / sudo** with your fingerprint.
- ⚠️ The secure session (SSLv3) is **fully reverse‑engineered and byte‑exact validated**, but the
  sensor enforces a pairing/provisioning gate we could not cross from the host — so, like every
  other VFS495 project, we let HP's proprietary binary establish the session (see
  [`docs/SSL_PROTOCOL.md`](docs/SSL_PROTOCOL.md)).

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

```
you swipe
  │
  ▼
validity-sensor (HP, proprietary)      ← establishes the SSLv3 session + captures
  │   harvested via gdb
  ▼
descramble (vfs495_descramble table) + the sensor's own motion-compensated assembly
  │
  ▼
tools/vfs495_capture_asm.py  →  clean 200×300 fingerprint (ridges dark)
  │
  ▼
tools/vfs495_bridge.py  →  libfprint's virtual_image socket (FP_VIRTUAL_IMAGE)
  │
  ▼
fprintd (NBIS minutiae + bozorth3)  →  enroll / verify  →  PAM (login, sudo, unlock)
```

- The **descramble table** (`driver/vfs495_descramble.inc`): the sensor reads its columns out of
  order; this permutation puts them back. Extracted from the running driver; regenerate with
  `runtime/dump_perm.gdb`.
- The **assembled image**: HP's `IRreconstructImage` produces a proper motion‑compensated print
  (far more consistent across swipes than naive stitching). We harvest it right before the
  proprietary quality gate. See [`docs/WRAPPER.md`](docs/WRAPPER.md).

## Repository layout

| Path | What |
|------|------|
| `tools/` | Capture, reconstruction, the fprintd bridge, and the (validated but blocked) pure‑Python SSLv3 client. |
| `runtime/` | The `gdb` harness scripts + `LD_PRELOAD` USB logger + how to stand up HP's binaries. |
| `driver/` | A scaffolded **native libfprint driver** (`vfs495.c`) + the protocol spec + descramble table. |
| `ghidra/` | Ghidra script to reproduce the decompilation/analysis. |
| `docs/` | `FINDINGS.md` (full RE log), `SSL_PROTOCOL.md`, `WRAPPER.md`, `SETUP_FPRINTD.md`. |

## Troubleshooting

- **Swipe timing.** When a prompt appears (login, `sudo`, `fprintd-enroll`), the sensor needs about
  2 seconds to arm (HP's binary is started and initialises the secure session). **Wait a moment,
  then swipe slowly**, whole fingertip, one steady motion. A swipe made instantly after the prompt
  is usually missed; just swipe again — the capture waits up to 60 s and retries once.
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

- **Capture uses HP's proprietary binary under `gdb`, as root.** It works, but it's a harness, not
  a driver, and needs HP's (freely downloadable) package present. The packaged bridge is
  **event-driven** (idle until fprintd reports `finger-needed`, cancelled when it stops), so it
  does not touch the sensor when nobody is authenticating.

## Roadmap

1. **Native libfprint driver** — port the decode/descramble/assembly into `driver/vfs495.c` so no
   `gdb`/proprietary harness is needed. The blocker is the secure‑session pairing gate; options are
   in `docs/SSL_PROTOCOL.md` (firmware analysis, or a signed‑patch/pairing path).
2. Or a proper capture‑helper around `libvfsFprintWrapper.so` (the community approach).

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

Built with a lot of `gdb`. PRs, especially toward the native driver, are very welcome.
