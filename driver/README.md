# Native libfprint driver (WIP)

A scaffolded libfprint driver for the VFS495. It implements the parts that are done — device
lifecycle, DLI line decode + column descramble, and swipe assembly via `fpi_assemble_lines` — and
clearly marks what remains (the sensor unlock: RAM patch upload + the SSLv3 session). The goal is a
driver that needs **no** gdb/proprietary harness. Today the working login path uses the harness +
`virtual_image` bridge instead (see ../docs/WRAPPER.md and ../docs/SETUP_FPRINTD.md).

## Files
- `vfs495.c` — the FpImageDevice driver.
- `vfs495_proto.h` — USB ids, endpoints, VCSFW command ids, geometry.
- `vfs495_descramble.inc` — the 264-entry column descramble table (extracted; regenerate with
  ../runtime/dump_perm.gdb). cols 0–199 = main image, 200–263 = an aux/nav sub-image.

## Build into libfprint
```bash
# libfprint 1.94.9 source:
curl -L -o libfprint.tgz https://gitlab.freedesktop.org/libfprint/libfprint/-/archive/v1.94.9/libfprint-v1.94.9.tar.gz
tar xf libfprint.tgz && cd libfprint-v1.94.9
cp ../vfs495.c ../vfs495_proto.h ../vfs495_descramble.inc libfprint/drivers/
```
Register it: in `libfprint/meson.build` add to `driver_sources`:
```
'vfs495' : [ 'drivers/vfs495.c' ],
```
and in the top-level `meson.build` add `'vfs495',` to `default_drivers`. Then:
```bash
meson setup build -Ddrivers=vfs495,virtual_image -Ddoc=false -Dintrospection=false \
  -Dgtk-examples=false -Dudev_hwdb_dir=/tmp/hwdb.d -Dudev_rules_dir=/tmp/rules.d
ninja -C build            # libfprint-2.so with "Validity VFS495"
```

## TODO (to make it standalone) — see ../docs/SSL_PROTOCOL.md
1. `ACTIVATE_UPLOAD_PATCH` — send `DOWNLOAD_PATCH` (cmd 0x06) with HP's getprint + security patch blobs.
2. `ACTIVATE_OPEN_SESSION` — the SSLv3 session. **Main blocker:** the sensor enforces a pairing/
   provisioning gate (fatal alert 0x2f) that we validated the crypto against but could not cross from
   the host. Leads in SSL_PROTOCOL.md.
3. Stream the image from EP 0x82; replace the placeholder line splitter with a faithful port of
   `irDliRTFalconData`; add the tool's assembly (`IRreconstructImage`) for match-quality output.
