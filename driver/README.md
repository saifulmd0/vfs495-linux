# Native libfprint driver for the VFS495

A libfprint image driver for the Validity VFS495 (`138a:003f`): secure session, capture and swipe
assembly in C, with no HP binary at runtime. It's an out-of-tree patch on libfprint 1.94.x. The design
and the measurements behind it are in [`PLAN.md`](PLAN.md); the protocol is in
[`../docs/FINDINGS.md`](../docs/FINDINGS.md) and [`../docs/SSL_PROTOCOL.md`](../docs/SSL_PROTOCOL.md).

## Files
| File | What |
|------|------|
| `vfs495.c` | The `FpImageDevice`: open (init sequence + SSLv3 session), capture loop, close (`close_notify`). |
| `vfs495_ssl.c/.h` | The session protocol (PRF, Validity's RSA byte order, Finished, record MAC/encryption) on OpenSSL. No USB. |
| `vfs495_setup.c/.h` | Parser for `setup.bin` (format: `../tools/make_setup_bin.py`). Pure GLib. |
| `vfs495_assemble.c/.h` | Swipe assembly, port of `../tools/vfs495_assemble.py`. Pure GLib + libm. |
| `vfs495_proto.h` | USB ids, endpoints, command ids, geometry. |
| `vfs495_descramble.inc` | The 264-entry column descramble table (0–199 main row, 200–263 second row). |
| `default.nix` | libfprint from nixpkgs with the driver added. |
| `tests/` | Offline tests and the hardware test (below). |

## The setup file
The driver needs `/var/lib/vfs495/setup.bin` (override: `VFS495_SETUP=PATH`). It holds the sensor's
init commands, including HP's firmware patches, and the setup commands sent before each swipe. They're
recorded once from your own sensor and can't be shipped:
```bash
sudo vfs495-setup     # ../runtime/vfs495-setup, Nix package ../runtime/default.nix
```
It runs HP's driver once under gdb, decrypts the setup commands from the USB trace
(`../runtime/trace_to_init.py`), packs them (`../tools/make_setup_bin.py`) and deletes HP's files. From
older recordings (`init_cmds.json` + `capture_cmds.json`): `python3 ../tools/make_setup_bin.py DIR setup.bin`.
Without the file, opening the device fails with a message that says so. More:
[`../docs/SETUP_FPRINTD.md`](../docs/SETUP_FPRINTD.md#native-driver).

## Build
Nix (any nixpkgs with libfprint 1.94.x):
```bash
nix build --impure --expr '(builtins.getFlake "nixpkgs").legacyPackages.x86_64-linux.callPackage ./driver { }'
```
On NixOS use the module (`../nixos/module.nix`), which also sets fprintd up. By hand, the patch is what
`default.nix` does: copy the files to `libfprint/drivers/vfs495/`, add `'vfs495'` to the driver sources
in `libfprint/meson.build` and to the driver list in `meson.build` with `'helper': ['openssl']`, and
remove `138a:003f` from the "known unsupported" list in `libfprint/fprint-list-udev-hwdb.c` (and move it to
the supported entries in `data/autosuspend.hwdb`, which libfprint's tests compare against).

## Test
Offline (cc, pkg-config, glib, openssl, python3 with numpy/scipy/cryptography):
```bash
tests/test_setup.sh                 # C parser == Python client on the recorded commands
tests/test_ssl.sh                   # session layer byte for byte against tools/ssl_session.py
tests/test_assemble.sh RAW.npy...   # C assembly == Python on recorded swipes (pixel-identical)
tests/test_setup_trace.sh           # vfs495-setup's trace extraction on synthetic HP traces
```
On the sensor, through the patched libfprint without fprintd (Nix, asks for sudo; stop fprintd first):
```bash
tests/hw_test.sh cycles 3                 # open / close
tests/hw_test.sh capture 10 /tmp/swipes   # swipes -> PGM
tests/hw_test.sh enroll-verify            # enroll one finger in memory, verify 3x
```
`hw_test.sh` packs a temporary `setup.bin` from `../captures/` unless `VFS495_SETUP` is set.

Debugging: `G_MESSAGES_DEBUG=libfprint-vfs495` logs each swipe (lines, assembly stats, retry
reason). `VFS495_RAW=DIR` saves the raw lines of each swipe as `swipe-NNN.npy`, for
`test_assemble.sh` and offline tuning. Those files are biometric data, so keep them local.
To score images with fprintd's matcher: `../packaging/vfs495-fprint/usr/bin/vfs495-match`.

## Startup latency
The old **bridge** backend (HP's binary under gdb + `FP_VIRTUAL_IMAGE`) took ~2 s to come up; the native
driver opens in ~0.6 s and should be the default (`services.vfs495.backend = "native"`). Of that 0.6 s the
only fixed delay is the 30 ms pause before each of the 8 init commands; back to back, the sensor resets
mid-init (a version that skipped the pause after query commands made the sensor re-enumerate on every
open, so it is applied to every command). It is tunable with **`VFS495_INIT_PAUSE_MS`** (default 30); only
lower it on a sensor you can test, and raise it if opens fail with `No such device`. The setup/arming replay
(on each activate) already runs back-to-back with no fixed pause; its cost is the USB transfers + the few
ep-0x82 calibration reads, not sleeps.

## Behaviour
- Open takes about 0.6 s. Close sends `close_notify`, so the next open doesn't reset the sensor. If a
  crashed process left a session open, the sensor resets itself and the open fails with a retryable error.
- One capture-loop run per swipe: setup commands with a fresh random image key, then poll for a finger
  every 50 ms, then the encrypted stream until the sensor's end-of-stream trailer, then abort and resync.
- Assembly runs in a worker thread (about 1 s per swipe).
- Retries: `TOO_FAST` when more than 25 % of the moving lines are at the speed-search floor;
  `TOO_SHORT` under 400 lines or the minimum image rows (default 80, override with `VFS495_MIN_ROWS` —
  the native equivalent of the bridge's `VFS_MIN_ROWS`).

## Distribution & upstreaming
How comparable libfprint sensors that need captured/proprietary setup data are handled (full-binary RE
reference: [`../docs/BINARY_RE.md`](../docs/BINARY_RE.md)):

- **This is the python-validity / open-fprintd model.** The `vfs0090`/`vfs0097` Validity sensors have the
  same dilemma (per-device init + firmware that can't be shipped). The established solution extracts the
  vendor firmware on the *user's own machine* and never redistributes it, running **out-of-tree** via
  `open-fprintd` (a drop-in fprintd D-Bus service) or a TOD module. Our `vfs495-setup` → `setup.bin` is
  exactly this pattern (we capture HP's signed RAM patches once, locally, and ship only the extractor).
- **libfprint policy** (`HACKING.md`) bans proprietary *code in the library*, not loading user-provided
  firmware — so a 100 %-free driver that reads a local `setup.bin` does not violate it. But upstream also
  wants 3 stand-alone devices + a protocol spec, and the active native-Validity MR (!626) is still unmerged
  after years, so **in-tree acceptance is unlikely near-term**. Plan to live out-of-tree (NixOS module / a
  COPR/PPA-style package), with the clean-room driver kept to upstream standards as insurance.
- **Never redistribute the captured `setup.bin` or any HP bytes** — the user captures them from their own
  device. That is the line that keeps this legally clean and the driver fully free/debuggable.
