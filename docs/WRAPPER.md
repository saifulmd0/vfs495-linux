# VFS495 working fingerprint path (proprietary-daemon wrapper)

This is the **realistic, working** route to fingerprint auth on the VFS495 (138a:003f),
matching what the whole community does: let HP's proprietary binary handle the sensor's
SSL session + capture, and keep the image processing + matching open. Proven end-to-end:
enroll + identify match the right finger and reject others.

## Pipeline
```
real sensor ──(HP validity-sensor getprintwait, does SSL+capture)──▶ descrambled scan lines
   │                                                                      │
   └── gdb harvest of UnpackLineRT output (runtime/harvest_lines.py)      │
                                                                          ▼
   tools/reconstruct.py  ── fixed-pattern removal + motion stitch ──▶ clean fingerprint (PGM)
                                                                          │
   tools/vfs495_bridge.py ── sends w,h,gray over FP_VIRTUAL_IMAGE ───────▶ libfprint virtual_image
                                                                          │
                                          NBIS minutiae + bozorth3 matcher ▶ enroll / identify (fprintd)
```

## Tools
- `tools/vfs495_capture.py [out.pgm]` — capture one fingerprint from the real sensor and write a
  clean 8-bit grayscale PGM (ridges dark). Needs sudo (USB) and gdb. Env: `VFS_TIMEOUT`, `VFS_ATTEMPTS`.
- `tools/vfs495_bridge.py` — client for libfprint's `virtual_image` socket. `--file img.pgm` sends a
  file; otherwise it captures live for each scan libfprint requests. Set `FP_VIRTUAL_IMAGE=<sock>`.
- `tools/reconstruct.py` — the reconstruction library (also a CLI on a lines.raw).
- `runtime/harvest_lines.py` — gdb script that harvests descrambled lines from validity-sensor.

## Proven (2026-09-15, libfprint 1.94.9 built here)
- Real capture -> reconstruct -> **libfprint enroll: 5/5 stages passed** (minutiae extracted fine).
- **identify: same finger -> "IDENTIFIED!"; different print (whorl sample) -> "NOT IDENTIFIED!"**.
  So the full auth machinery works and discriminates.

## Wiring to fprintd (login) — outline
1. Build/patch libfprint with the `virtual_image` driver enabled (done in driver/libfprint/build).
2. Point fprintd at the socket (drop-in unit):
   `Environment=FP_VIRTUAL_IMAGE=/run/fprint/virtimg_sock` + `RuntimeDirectory=fprint`.
3. Run `vfs495_bridge.py` (as root, with FP_VIRTUAL_IMAGE set to the same socket) so each scan fprintd
   asks for is served by a live sensor capture.
4. `fprintd-enroll` / PAM `pam_fprintd` then work through the bridge.
   (A cleaner long-term option is a proper libfprint driver whose `activate` shells out to the
   capture helper, instead of the virtual_image socket — but virtual_image is the quickest working bridge.)

## *** CROSS-CAPTURE MATCHING SOLVED (2026-09-15) ***
The fix: use the TOOL'S OWN motion-compensated assembly (IRreconstructImage), not our reconstruct.py.
The assembled 200x300 image lives at IR-ctx+0xa8 (dims at ptr-0x44/-0x48) and is built BEFORE the quality
gate (IRqualityDetermination @0x4689b0) that "fails", so we harvest it there via gdb.
- runtime/harvest_assembled.py: gdb dumps the assembled image at IRqualityDetermination entry.
- tools/vfs495_capture_asm.py: capture -> match-quality PGM (200x300, ridges dark). Use THIS, not
  vfs495_capture.py, for enrollment/verification. vfs495_bridge.py now calls it.
- RESULT: enroll swipe#1, identify a DIFFERENT swipe#2 of the same finger -> **bozorth3 score 79/40 ->
  IDENTIFIED!**; a different finger (whorl sample) -> **score 5/40 -> NOT IDENTIFIED**. Reliable auth.
The image is far cleaner than our reconstruction (proper whorl/core, correct aspect, no distortion) because
the sensor's host code does real per-line motion compensation. This is the working capture path.

## (superseded) CROSS-CAPTURE MATCHING: the earlier hard problem
Same-image identify matches; two DIFFERENT swipes of one finger do NOT yet reliably match.
Diagnosis (2026-09-15, after reboot, clean sensor):
- Two real swipes of one finger: horizontal ridge period consistent (~10-12px = true sensor res), but
  VERTICAL (swipe-axis) ridge period is 62-116px and INCONSISTENT (swipe-speed oversampling) -> geometry
  differs per swipe -> minutiae don't align.
- Fix attempted: isotropic_v() resamples the swipe axis so vertical ridge spacing == horizontal. This is
  the right direction — cross-capture bozorth3 score went from ~0 (plain resize) to **18/40** (threshold 40).
  Different fingers still score ~0, so it's discriminating, just under threshold.
- Blocker: swipes capture too little finger -> after isotropic compression images are only ~80-190 rows
  (few minutiae). Need FULL, slower swipes (whole fingertip) + consistent extent, and/or better local
  motion compensation (current reconstruct uses a global novelty-resample, not per-line displacement).
- Best path to match-quality images: use the proprietary libvfsFprintWrapper.so's own assembly (what
  vcsFPService/rindeal use) instead of our reconstruct.py — it does proper motion compensation. That is
  the next lead if reconstruction tuning stalls.

## KNOWN ISSUE: capture reliability
`getprintwait` (the descrambled path) can get stuck returning only ~39 lines after many rapid
back-to-back runs (wake-on-event state not re-arming). A full **laptop power-off/on** restores it
(USB re-enumeration alone does NOT). The plain `getprint` raw path keeps working but gives a poorer,
non-descrambled 200-line window. When the sensor is fresh, getprintwait yields ~3130 lines and clean
prints. Add spacing between captures and avoid dozens of rapid runs.

## Why not reimplement the SSL?
Nobody has (rindeal, sq4, zvoznikau, ryantrinkle all wrap the proprietary daemon). Our full SSLv3
reverse-engineering + a byte-exact-validated client is in tools/ssl_session.py + driver/SSL_PROTOCOL.md,
but it hits a sensor-side provisioning/pairing gate (alert 0x2f) we could not cross from the host. The
proprietary binary already does the SSL correctly, so we delegate it — the pragmatic, working choice.
