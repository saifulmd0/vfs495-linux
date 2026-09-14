# VFS495 (138a:003f) reverse-engineering notes

## Device
- USB 138a:003f, bcdDevice 1.04, one vendor-specific interface (class 255)
- EP 0x01 bulk OUT (64), EP 0x81 bulk IN (64), EP 0x82 bulk IN (64), EP 0x83 interrupt IN (8)

## Sources
- hp-linux/sp84530.tar (md5 9877c69c4f4b57a00f9e4afbcd9baacc) — Validity-Sensor-Setup-4.5-136.0 (SLED 11), extracted to hp-linux/rpm/
- hp-win/sp70364.exe (md5 163252c58705f09eb3af151a58e2fc75) — EliteBook Folio 1020 G1 Win7 x86 driver pack, contains Validity driver 4.5.133.0
- Tools: ~/tools/ghidra_12.1.3_PUBLIC (needs openjdk-21-jdk)

## Findings (step 1, static)
- `usr/sbin/validity-sensor` (2.8 MB, NOT stripped, 2686 functions) — vendor diagnostic CLI; best Ghidra target.
- `usr/bin/vcsFPService` (2.5 MB, stripped) — the daemon; same codebase.
- Both use libusb-0.1 API (usb_bulk_read/write, usb_reset, set_configuration...) -> easy to trace with usbmon/LD_PRELOAD.
- Crypto statically linked (not OpenSSL imports): AES (ECB/CBC/CTR), DES, RSA-2048, ECC, DH, HMAC-SHA256.
  Relevant: scsDHEstablishSessionKey, scsSensorIsAESSecured, scsSensorIsECCSecured, GetSensorPubKey.
- Sensor family codename "Falcon": scsFalconDeviceInit, scsSensorFalconCalibrate (ADC/PGA/LNA cal), WOE (wake-on-event) setup.
- Firmware "patches" are downloaded to the sensor: LoadPatch, LoadSecurityManagementPatch,
  scsDownloadGetPrintPatch / RunPatch / SecureMatchPatch / AuthPatch / FlashPatch, scsCreateSignedPatch.
- `usr/sbin/HPUsbVFS495.img` (315392 B) and siblings: entropy 7.999 -> encrypted/compressed; likely patch container.
- Sensor has SPI flash (flashinfo command strings).

## Windows pack (sp70364)
- Validity folder only has vfs4xx.inf binding 138a:003f to generic WinUSB.sys (DriverVer 2.3.0.0) + MS co-installers.
- No Validity logic in it: the real code is a userland WBF adapter/service shipped in a separate package.
- Implication: on Windows all sensor traffic is plain WinUSB bulk I/O from userland -> USBPcap capture will see everything.
- Linux package remains the primary static-analysis target.

## Step 1 progress (Ghidra, validity-sensor decompiled -> ghidra/out/validity-sensor.c, 2778 funcs)
- .img files: header "_VEH" + "HPUsbVFS495.efi" + "VALIDITY" — look like HP pre-boot (UEFI) modules, body
  probably compressed. Sensor patches used by the tool are compiled into the binary instead
  (secMgmtFalconPatchList, falconPatchConfigList, scsSensorLoadPatch(..., phase mask)).
- Protocol = VCSFW command/reply: vcsTestSensorSendCommand(buf,len,reply,&replylen); reply starts with u16 status.
  GET_VERSION = cmd 0x01 (1 byte), reply <=0x26 B: status u16, buildtime u32, buildnum u32, vmajor, vminor,
  target, product (1 Falcon,3 Falconusb...), siliconrev, formalrel, platform, patch, serial[6], security[2],
  patchsig u32, iface. GPIO = cmd 0x0d. Same VCSFW family as python-validity (138a:0090/0097) -> prior art.
- getprint help: "If enc is specified, fingerprint will be encrypted by sensor" -> plaintext capture by default.
- Dangerous persistent writes only from explicit commands: OTP write (provision/serialize/set_prod_opts/makeprod/
  write_otp), spiflashwrite, ownership cmds. Patches go to sensor RAM (unloadpatch exists).
- HP build's main() only dispatches "setowner -doinit" / "resetowner -doinit"; all other commands print
  "Request failed". Execute() @0x4403b0 is the normal dispatcher. gMode default 0x80300000; -doinit clears bit31.
- runtime/: openssl 0.9.8 stubs + libusb-0.1 (from deb) + usblog.so LD_PRELOAD logger. Tool starts OK.

## Hardware runs
- runtime/vs.sh = allowlisted wrapper (sudo) around runtime/bin/validity-sensor-unlocked (main gate jmp @0x44122d).
- 2026-09-14 `getver` (no -doinit): "Sensor Version 04.60.00.0104 Falcon ROM". Traffic was ONLY:
  set_configuration 1, claim_interface 0, set_altinterface 0, OUT ep01 `01`, IN ep81 38 bytes:
  <GetVersion reply, 38B — contains per-device serial; redacted>
  -> status 0, buildtime 0x4d52ef1a, build 104, v4.60, target ROM, product 3 Falconusb, siliconrev 0,
     formalrel 1, platform 0x0b, patch 0, security 01 7d, patchsig 0 (no patch loaded), iface 1 USB.
  Note: `provision vfs495` help mentions "clean 4.60.0104 sensor" = same ROM version as ours.
- Command table (FunctionList @0x8705e0, 0x36 entries) dumped; write_otp not present in table.
- getprint handler uses vcsTestGetRawScanlines / vcsTestPeek / GetConfiguration (raw scanlines).
- tools/vcsfw_getver.py: independent pyusb GET_VERSION client.

## Option 1 result: -doinit / getprint is safe (no persistent sensor writes)
- Command IDs (VCSFW, from *_V4 senders): 01 GetVersion, 02 GetConfiguration(0x15... actually cmd byte
  first), 04 AbortFingerprint, 05 Reset, 06 DownloadPatch, 07 Peek, 08 Poke, 09 RefClock, 0b SPITrans,
  0c(WOEEnter uses 0x0c?), 0d GPIO, 0x13 SetCPUClock, 0x15 GetFingerprint/GetConfiguration,
  0x17 GetFingerState, 0x19 GetStartInfo, 0x1a UnloadPatch, 0x1b Lock, 0x1c MatchVerify,
  0x1d SignEnc, 0x1e DecVerify, 0x24/0x2a LED, 0x26 GetOwnershipInfo, 0x27 GetUID, 0x29 Cert.
- Wire framing (scsSend @0x4f7bd0): [cmd byte][payload]; SSL-wrapped only if secure session (scsSSLEncrypt,
  skipped when param8!=0). Our sensor: not secure, no SSL -> plaintext (matches getver/getstartinfo bytes).
- DownloadPatch (cmd 06): body = 0x06 || patchbytes. If sensor secured, patch is signed first
  (scsCreateSignedPatch); ours is unsecured -> raw patch bytes.
- Reachability from {FalconCalibrate, DownloadGetPrintPatch, SendGetFingerprint_V4, LoadPatch}:
  NONE reach _xvfsWriteFlash / EraseFlash / vcsTestSensorOtpWrite / Poke / SPIFlash / StorageWrite.
- SPIFlash_V4 / StoragePartWrite_V4 / all Db*_V4 return 0xdd (not implemented in this build).
- "Persistent data" = HOST file /etc/ValidityPersistentData (palReadAllPersistentData), NOT sensor flash.
  Calibrate only reads it (palGetPersistentDataLongValue) + loads RAM patch. Safe.
- Conclusion: `getprint -doinit` writes nothing permanent to the sensor. Patches live in RAM (unloadpatch clears).

## getprint -doinit CAPTURE SUCCESS (2026-09-14) — GO
Sequence on the wire (ep1 control, ep2 image DMA):
  01 GetVersion -> 19 GetStartInfo -> 06 DownloadPatch(693B) -> 01 GetVer -> 1f SPIBulkRead(flash id/read)
  -> 06 DownloadPatch(1301B, security-mgmt) -> 01 GetVer(now patch bits set)
  -> 0x11 TLS tunnel: SSLv3 handshake (records 16 03 00 ...; ServerHello type 02, 32B random)
  -> control commands now TLS app-data (17 03 00 ...), MISLABELED as "GetFingerState" by id-only decoder.
KEY: ep2 image data is PLAINTEXT grayscale, framed 01 fe 01 00 <flags> c8 00 <pixels ~0x70-0x92>.
  Empty-sensor baseline rendered: 272 x 1023, mean 124, vertical column pattern, no ridges. Looks correct.
  -> ghidra/out corrected: getprint DOES establish SSL3 on control channel, but the RAW IMAGE stays clear.
Files (in capture dir): FingerPrint.bin (278256B raw scanlines), FingerPrint.csv (decoded), baseline.png.
Implication for driver: replicate 06 patch uploads + 0x11 SSL3 handshake for control, then read plaintext
  image frames from ep2. Prior art = libfprint vfs301/vfs5011 (same 01fe framing family).

## Frame geometry decoded + reconstruction status (2026-09-14)
- ep2 frames are 01/fe delimited (irDliRTFalconData @0x462350 uses palMemchr for 0x01, checks 0x01/0xfe,
  line-width cap 0x13f=319). vcsTestGetRawScanlines ALREADY runs this reassembly, so FingerPrint.csv rows
  ARE the correctly separated per-scanline pixels. My per-row rendering geometry was therefore correct.
- Ridge signal IS present: ridge-band (6-12px) energy in swipe = 4.2x the no-finger baseline; per-row
  stddev 26->41. So sensor+capture path genuinely record ridges.
- BUT no coherent ridge FLOW in any render (baseline-subtract, bandpass, motion-resample all tried).
  Likely cause: capture #221004 shows finger contact on ALL 1023 lines (not the partial-window a clean
  swipe gives) -> finger was held/too-slow, so little spatial travel = no 2D print. VFS495 is a SWIPE sensor.
- Also not yet replicated: HP's per-timeslot baseline subtraction + diff-line processing (fclBvs sections:
  BaselineImage, DiffLineLenLines, RawDataTrim, BitReduction). Our baseline is from a separate -doinit so
  its per-timeslot calibration may not align. Proper path = replicate libfprint vfs301 assembly on raw frames.
- NEXT: (a) get a clean swipe (quick, light, continuous top->bottom drag, ~1s) so finger occupies a
  partial line-window; (b) implement vfs301-style assembly (per-frame baseline sub + motion stitch) in
  tools/. Render scripts live inline in capture dirs; consolidate into tools/reconstruct.py next.

## Clean finger swipe captured (2026-09-14, getprintwait -doinit)
- `getprint` doesn't wait -> kept missing the swipe (timing). `getprintwait -doinit` blocks up to 60s
  (vcsTestSensorGetFingerprint ...,60000) and caught a real swipe. 893 transfers, ep2=1.49MB.
  NOTE: getprintwait keeps the image in RAM, writes NO FingerPrint.csv -> must parse ep2 from usb.log.
- Best raw capture preserved: captures/BEST-swipe-getprintwait.usb.log.
- PLAINTEXT confirmed by entropy: ep2 H≈6.0 bits/byte (not ~8 => not encrypted). Baseline H=4.45.
  Ridge/valley contrast visible at byte level, e.g. `8a71 8973 8a71` = 138/113 alternating.
- ep2 frame header decoded: `01 fe [seq:u16 LE] [f4] [f5] [width:u8] 00` then pixel bytes.
  seq increments 1,2,3...; width seen = 200(c8)/216(d8)/152(98)/136(88). f4/f5 flags (often 01 01 or 00 00).
- OPEN DECODE PROBLEM (blocker for a clean render): strict length-follow (advance 8+width) stays aligned
  for only 2 frames then hits non-header pixel data => the width byte is NOT the full line/frame length,
  OR frames carry multiple sub-lines / a trailer. Scanning for the 01fe magic drifts because ridge pixel
  data legitimately contains 01/fe/00 bytes. Need to decode the true line count/length from
  irDliRTFalconData @0x462350 (the 0x13f=319 cap and the 0x150 running-length field there are the key).
- Interpretation: dual/interleaved frame TYPES (main image + navigation/tracking image, like Validity
  swipe sensors). f4/f5 or width likely selects type. Reconstruction = demux main-type frames, then
  motion-stitch (prior art: libfprint vfs301/vfs5011 assembly).

## FRAME FORMAT FULLY DECODED (from irDliRTFalconData/UnpackLineRT/ProcessTimeslotTable)
Two capture paths, IMPORTANT difference:
- `getprint`/getprintwait->FingerPrint.csv uses vcsTestGetRawScanlines = RAW timeslot-order scanlines,
  NOT descrambled, NOT DLI-decoded (verified: that path never calls irDli/Unpack/Timeslot). 272 wide.
  Columns are only mildly permuted (neighbor-corr ~0.30, greedy reorder doesn't help) -> the 221004
  "banding" is a bad swipe (finger held/too slow = no motion = no 2D print), not a scramble problem.
- `getprintwait` (vcsTestSensorGetFingerprint) runs the FULL pipeline: irDliRTFalconData -> UnpackLineRT
  -> descramble via ProcessTimeslotTable -> vcsDoIR. Output stays in RAM (no file). ep2 carries the
  compressed DLI stream.

DLI line format (per irDliRTFalconData @0x462350, UnpackLineRT @0x46f510):
- Lines delimited by marker byte 0x01 whose NEXT byte is 0x01 or 0xfe. Scanning for magic drifts because
  ridge pixel data contains these bytes; the parser instead accumulates to a fixed frame_size
  (ctx+0x170) and splits, so a correct reimpl must track running length, not scan.
- First 8 bytes of each line = header (copied verbatim), then payload.
- Decode mode = header byte[6] & 0x0f (the "scale" nibble). Our captures: byte6 in {c8,d8,88,98} -> nibble
  8 => 8-BIT DIRECT (one payload byte per pixel). nibble 4 => 4-bit (two px/byte, hi<<4 & lo&0xf0).
  else => bit-unpack with per-pixel bit-lengths from cfg[+8] table, mask table {1,3,7,f,1f,3f,7f,ff}.
- Output pixels are SCATTERED through a permutation: out[ perm[i] ] = pixel_i, perm = int16 table at
  cfg+0x57c. So descramble is mandatory for a coherent image.
- perm table built by ProcessTimeslotTable @0x46f1c0 from the sensor TIMESLOT TABLE: width =
  cfg[0x11]+cfg[0x19]; each 32-bit timeslot entry: bits0-8=column(&0x1ff), bits26-29=phase(>>0x1a&0xf),
  bits21-22=group(>>0x15&3); entries with phase!=0 and col!=0x1ff map to successive output positions.
  Range descriptor at timeslottable+0x5d8: (val&0x1ff)-1 .. ((val>>9)&0x1ff)-1.
- => To reproduce: capture the timeslot table (getconfig -doinit returns it) and port ProcessTimeslotTable
  + UnpackLineRT. This is exactly what libfprint vfs301/vfs5011 already implement for the sibling sensor.

## *** REAL FINGERPRINT DECODED (2026-09-14) ***
Got a clean, recognizable fingerprint image (loop core + minutiae) end-to-end on Debian 13.
Method that worked (the timeslot table is TLS-encrypted on the wire, so DON'T sniff it):
- getconfig -doinit "succeeds" but reply is inside the SSLv3 control channel -> not sniffable.
- Instead harvest from RAM with gdb: break at UnpackLineRT (0x46f510); it receives the FULLY BUILT
  descramble table + width in its config arg and writes the descrambled line to the output buffer (RDX).
- runtime/dump_perm.gdb: dumped width=264, scale=8 (8-bit direct), perm table (264 int16, true permutation
  of 0..263, saved runtime/perm.bin + captures/perm.bin) and bitlen table (all 8). perm[:8]=199..192 desc.
- runtime/harvest_lines.py: gdb-python, breaks at UnpackLineRT, one-behind dump of RDX+8 (264 bytes each)
  to captures/lines.raw as [u16 len][data]. One swipe -> 3130 lines x264, all decoded+descrambled by the
  tool itself (no fragile wire parsing). NOTE: "vcsTestSensorGetFingerprint failed" = HP quality gate only;
  the raw lines are still captured.
- Reconstruction (ad-hoc, in captures/): stack lines -> subtract per-column fixed pattern -> bandpass +
  local-contrast normalize -> crop finger-active window (energy-based). Output captures/fingerprint.png.
  Swipe had a pause -> a faint doubled print on the right (needs swipe de-dup/stitch).

## Stitching DONE (tools/reconstruct.py)
- Pipeline: load lines.raw -> subtract fixed column pattern -> bandpass -> per-row ridge ENERGY selects the
  finger-present segment (bridge <120-row dropouts; energy, NOT novelty — novelty is high in no-finger
  noise too) -> novelty (1-corr of consecutive lines) resamples to uniform finger displacement -> local
  contrast normalize -> print_stitched.png.
- Result: single clean print, loop core + ridge flow, proportions corrected. captures/print_stitched.png.
  Right-edge vertical striping = low finger contact at sensor edge (cosmetic; mask low-variance cols later).
- Column analysis: 264-wide line is ONE image (uniform col energy, no sub-image split); earlier "double"
  was natural ridge flow, not a duplicate.

REMAINING TO A DRIVER:
1. (optional polish) mask low-contact edge columns; auto-orient.
2. Port to a libfprint 1.94 driver (vfs495) based on vfs301/vfs5011: replicate patch upload (cmd 06) +
   SSL3 open + DLI line decode (UnpackLineRT: 8-hdr, scale nibble, perm descramble) + assembly.
   We now have: exact command IDs, wire framing, the descramble perm table, and proof the image is good.
Feasibility: DONE/PROVEN with a real print. The rest is standard driver implementation.

## libfprint DRIVER SCAFFOLD BUILT (2026-09-14)  -> driver/
- libfprint 1.94.9 source in driver/libfprint/ (matches installed lib version).
- driver/vfs495.c + vfs495_proto.h + vfs495_descramble.inc, registered in both meson.build files.
- BUILDS CLEAN: meson setup build -Ddrivers=vfs495,virtual_image -Ddoc=false -Dintrospection=false
  -Dgtk-examples=false -Dudev_hwdb_dir=/tmp/hwdb.d -Dudev_rules_dir=/tmp/rules.d ; ninja -C build
  -> libfprint-2.so.2.0.0 contains "Validity VFS495". (udev.pc missing on Deb13 -> pass hwdb/rules dirs.)
- Implemented: FpImageDevice lifecycle, id_table 138a:003f, SWIPE, DLI 8-bit decode + descramble,
  fpi_assemble_lines assembly over main 200 cols. Descramble table = perm reversal (cols 0-199 main
  image, 200-263 aux/nav sub-image -- confirms the earlier "double").
- TODO (see driver/README.md): patch upload (cmd 06 blobs), SSLv3 session (cmd 0x11 tunnel, DH key) =
  main blocker, ep2 capture via fpi_usb_transfer + irq finger event, port irDliRTFalconData framing.
  reconstruct.py + harvest_lines.py are the behavioral spec.
- Build deps installed: meson ninja pkg-config libglib2.0-dev libgusb-dev libnss3-dev libpixman-1-dev
  libgudev-1.0-dev libgirepository1.0-dev libudev-dev libcairo2-dev cmake gdb.

## SSL SESSION FULLY REVERSE-ENGINEERED (2026-09-14) -> driver/SSL_PROTOCOL.md
- Capture cmd 0x02 is REQUIRED to be inside SSL: plaintext 0x02 after init -> status 0x0404 denied
  (verified, tools/test_nossl.py). So the session is mandatory; no shortcut.
- It is proprietary SSLv3 with custom cipher-suite IDs 0x0042/43/44 = AES-128/192/256-CBC + SHA1.
  Chosen: 0x0044 AES-256-CBC-SHA. All standard primitives (RSA-2048, MD5, SHA1, AES-CBC).
- Key exchange = RSA: 48B premaster (03 00 + 46 rand) encrypted with the SENSOR's RSA-2048 pubkey
  (exp 65537, modulus read from sensor storage id 10 via scsGetDataFromStorage @0x511c30; dumped to
  captures/rsa_modulus.bin). RSA output is byte-reversed. No cert sent by server.
- Master secret + key block = SSLv3 MD5/SHA1 KDF (exact formulas in SSL_PROTOCOL.md). Key block 136B:
  cMAC20 sMAC20 cKey32 sKey32 cIV16 sIV16. MAC = SSLv3 SHA1 (scsSSLMacSha). Finished = SSLv3
  (labels CLNT/SRVR). Records: handshake tunneled in cmd 0x11; AppData raw as 17 03 00 ...; image
  still PLAINTEXT on ep 0x82.
- gdb dumpers: runtime/dump_rsa.py (RSA key), dump_ssl.py (premaster/master/keyblock ->
  captures/ssl_secrets.json), harvest_cmds_full.py (all plaintext cmds -> plaintext_cmds_full.txt),
  init_cmds.json (pre-SSL init sequence for replay).
- Driver: ACTIVATE_UPLOAD_PATCH + ACTIVATE_OPEN_SESSION states now documented with the exact steps;
  still compiles. Patch blobs are HP IP -> load from HP package at runtime, do NOT embed.

## REMAINING FOR SSL (the actual coding, next):
1. Build a Python PoC (cryptography lib is installed) implementing SSL_PROTOCOL.md end-to-end: init ->
   ClientHello -> ServerHello -> fetch RSA key (storage id 10) -> ClientKeyExchange -> KDF -> CCS/Finished
   -> send capture cmd 0x02 as AppData -> read plaintext image. Validate KDF vs ssl_secrets.json first
   (capture that session's randoms via a scsSSLClientHelloWrite/ServerHelloProcess breakpoint).
2. Port to vfs495_ssl.c (NSS) + wire fpi_usb_transfer capture in the driver.
3. Find/port the storage-read command bytes for scsGetDataFromStorage(id 10) so the driver fetches the
   RSA key at runtime instead of a baked constant.

## SSL PoC (2026-09-15): ALL CRYPTO VALIDATED, handshake blocked at sensor alert 0x2f
tools/ssl_session.py implements the full SSLv3 client. Every primitive VALIDATED byte-exact vs gdb dumps
of the real driver:
- KDF master+keyblock (kdf_vector.json) MATCH; Finished (finished_vec.json) MATCH — label = LE int
  0x434c4e54 (bytes 54 4e 4c 43); record AES-256-CBC + MAC (rec_vec.json) MATCH — MAC OMITS length.
- RSA (rsa_em*/wire_order.json): modulus stored LITTLE-ENDIAN, exp 65537, PKCS#1 v1.5, wire=big-endian C.
  pow(EM_be,65537,n_le)==C and wire==C_be both verified. (Baked as defaults in the PoC.)
gdb dumpers added: dump_kdf.py, dump_finished.py, dump_rec.py, dump_rsakey.py, dump_em3.py, dump_wire.py.
Reference vectors: captures/{kdf_vector,finished_vec,rec_vec,rsakey,rsa_em3,wire_order,hs_templates,
init_cmds}.json. authoritative RSA modulus: per-device, regenerate via runtime/dump_rsakey.py.

BLOCKER: sensor rejects the CKE+CCS+Finished flight with fatal alert `15 03 00 00 02 02 2f` (desc 0x2f).
ClientHello is ACCEPTED (ServerHello 58B parses: SH+ServerHelloDone). Framing byte-matches the capture
(ClientHello tunnel 11 3c 00; flight tunnel 11 54 01 = CKE265+CCS6+Fin69). Tested: both RSA byte orders,
both modulus endianness, MAC with/without length, ServerHelloDone in/out of hash, split vs single tunnel,
drain extra reads, full USB re-enumeration (fresh state). All -> 0x2f. 0x2f is SENSOR-FIRMWARE generated
(not in host decompile), so its trigger is opaque. NEXT: capture MY session via usbmon and diff structurally
vs BEST-swipe; try replicating the exact capture ordering incl. any post-ServerHello 1a/06 commands; and
verify the premaster version-byte check against the negotiated version. Confidence the crypto is right is
very high (all byte-exact); the gap is a sensor-side protocol nuance.

## usbmon/wire DIFF done (2026-09-15): my session == tool's, byte-structurally
Logged my PoC's full traffic (captures/my_session.json) and diffed vs the tool's BEST-swipe capture,
message by message. RESULT: identical command sequence and identical framing end-to-end —
  init 01 19 06 01 1f 1f 06 01 (replies match; only GetStartInfo content differs = sensor boot state),
  ClientHello tunnel `11 3c 00 1603000037 01000033 0300 <rand32> 07 <sid=00*7> 00 06 004400430042 00`,
  ServerHello `...0300 <srand32> 07 46414c4353534c("FALCSSL") 0044 00 0e000000` (SH+ServerHelloDone),
  2nd flight tunnel `11 54 01` = CKE(16 03 00 01 04 | 10 00 01 00 | 256) + CCS(14 03 00 00 01 01) +
    Finished(16 03 00 00 40 | 64).
The ONLY differences are the random values and the encrypted bytes derived from them. Tool's flight ->
server CCS+Finished (144B, success); my identical-structure flight -> alert 0x2f.
=> The blocker is isolated purely to CRYPTO CONTENT, where every primitive is validated byte-exact
   (KDF, Finished, record enc, RSA). Also ruled out live: client/server random swap in KDF.
Since 0x2f is sensor-firmware generated and structure/primitives are all confirmed, the next real lead is
NOT host-side. Options: (a) obtain/analyze the sensor firmware image; (b) try enrolling the sensor state
via the tool once, then run the PoC (maybe first-contact provisioning state matters); (c) exhaustive
micro-variations of the premaster/version bytes. This is a deep sensor-side nuance; host-side RE is complete.

## Provisioning-state lead + content-independence tests (2026-09-15) — still 0x2f
- Priming: ran the tool's `getprint -doinit` (full init + successful SSL) then immediately my PoC -> still 0x2f.
- id 11 storage (read in scsSSLEstablishSession) = a CERTIFICATE that the HOST uses to validate the id-10
  modulus (scsSensorValidateCertificate); it is NOT sent on the wire -> not our problem. RSA key = id 10.
- Content-independence: premaster version bytes {0300,0000,0303,0301} ALL -> same 0x2f; heavily corrupting
  the CKE ciphertext -> same 0x2f. So the rejection does not vary with CKE/premaster content.
  Interpretation: consistent with the sensor failing at the (encrypted) Finished stage the same way whether
  the premaster is right or wrong — i.e. the client Finished never verifies. Given ssl3_finished + KDF +
  record-enc are all byte-exact vs the tool and hs-message composition matches, this points to a subtle
  live-state difference the host wire-trace does NOT reveal.
- One remaining wire-observable difference: GetStartInfo(19) reply = sensor boot/reset state
  (tool: WOE(2)/POWERON(0); mine after re-enum: type 3 / reset 4). Worth forcing WOE/POWERON before SSL.
- HONEST STATUS: host-side RE of SSL is complete and every primitive validated byte-exact, but the live
  handshake is rejected for a reason not visible from the host. Real next leads need sensor-side insight:
  extract/analyze sensor firmware; or gdb-instrument the TOOL to dump its handshake-hash + expected client
  Finished for a live session and compare against my computation on the SAME (dumped) inputs end-to-end.

## FINAL SSL validation (2026-09-15): every link confirmed, still 0x2f
- Verified ctx+0x38 == ClientHello random and ctx+0x40 == ServerHello random (rand_check.json) — so my
  client/server-random extraction offsets and KDF roles are correct.
- COMPLETE validation ledger (each MATCHES the real driver byte-exact): random extraction; master=PRF(pre,
  cR,sR); keyblock=PRF(master,sR,cR); keyblock split cMAC/sMAC/cKey/sKey/cIV/sIV; SSLv3 Finished (LE label);
  record AES-256-CBC + length-less MAC; RSA (LE modulus, e=65537, PKCS#1, big-endian wire). Wire trace
  byte-identical to the tool through the whole handshake.
- Also ruled out: dev.reset()/boot-state, tool-priming, random-order swap, premaster version, CKE corruption.
- CONCLUSION: there is no remaining host-observable difference. The sensor rejects a byte-structurally
  identical, cryptographically-validated flight. The cause is inside the sensor firmware (0x2f originates
  there) and is not resolvable from host-side RE with the current toolset. This is THE blocker for the driver.
- Realistic paths forward (all need new capability, not more host tweaking):
  1. Dump/analyze the sensor firmware (the .img files? or SPI flash dump) to see the server-side SSL check.
  2. Compare against python-validity (sibling 0090/0097) for a shared quirk in this SSL variant.
  3. Timing: my Python is much slower than the C tool between ServerHello and the flight — try a native/
     tightened client, or async, in case a sensor-side timeout manifests as 0x2f.

## RESEARCH (2026-09-15): firmware image + python-validity comparison -> PIVOT recommendation
- Firmware: NO standalone downloadable VFS495 sensor firmware (the server-side SSL runs on the sensor's
  internal firmware, not distributed). We already have HP's HPUsbVFS495.img + proprietary binaries from
  sp84530. So no host-side artifact to diff against for the sensor's SSL check.
- python-validity = NEWER 0090/0097 (Prometheus): TLS 1.2 + ECDH-ECDSA (suite 0xc005), NOT our SSLv3+RSA.
  Architecturally different, but its central lesson: these sensors are PAIRED/PROVISIONED to a host; the
  handshake fails if unprovisioned ("device was probably paired with another computer"). Device stores keys
  encrypted with a host-identity-derived PSK (product_name+serial). => our 0x2f is very likely a sensor-side
  provisioning/pairing GATE, not a crypto bug (consistent with our byte-exact validation + identical wire).
  Note: our KDF validation shows the VFS495 master secret is NOT host-bound, so any binding is a separate
  gate the sensor enforces, opaque from the host.
- **KEY FINDING: nobody has ever reimplemented the VFS495 secure session in open code.** ALL community
  VFS495 drivers (rindeal, sq4, zvoznikau, ryantrinkle — all from Balint Banyasz's work) DELEGATE to the
  proprietary vcsFPService daemon + libvfsFprintWrapper.so and just pipe the image to libfprint. Our SSL
  wall is the same one the whole community hit and worked around.

## RECOMMENDED PIVOT (realistic path to a WORKING driver)
Do NOT keep reimplementing SSL. Instead wrap the proprietary stack we already have (from sp84530):
vcsFPService + libvfsFprintWrapper.so establish SSL + capture correctly on THIS machine — that's how we
already captured the real fingerprint (via validity-sensor getprintwait). Build the driver like rindeal's:
a capture-helper process loads the proprietary lib, does the capture, pipes the raw image out; feed it
through our validated descramble (perm.bin) + reconstruct.py stitching + fpi_assemble_lines. Our open
vfs495.c decode/descramble/assembly stays; only the SSL+capture is delegated to the proprietary binary.
Keep tools/ssl_session.py as-is (all crypto validated) in case the pairing gate is ever cracked.

## *** WORKING AUTH PIPELINE (2026-09-15) — proprietary-daemon wrapper *** see WRAPPER.md
Built the community-style path: proprietary validity-sensor does SSL+capture; open code does the rest.
PROVEN end-to-end with libfprint 1.94.9 (built in driver/libfprint/build):
- tools/vfs495_capture.py: real capture -> descramble -> reconstruct -> clean PGM (ridges dark, main 200 cols).
- tools/vfs495_bridge.py: feeds images to libfprint virtual_image socket (FP_VIRTUAL_IMAGE).
- libfprint ENROLL: 5/5 stages passed (minutiae extracted from our reconstructed print).
- libfprint IDENTIFY: same finger -> "IDENTIFIED!"; different print (whorl sample) -> "NOT IDENTIFIED!".
  => full NBIS enroll+match works and discriminates. This is a working VFS495 fingerprint auth path.
- Bridge->virtual_image->img-capture round-trip verified too.
Caveat: identify match above used the same capture as enroll (proves the machinery); true cross-swipe
matching needs the sensor reliably capturing. KNOWN ISSUE: getprintwait degrades to ~39 lines after many
rapid runs (WOE not re-arming); a full laptop POWER CYCLE restores it (USB re-enum does not). getprint raw
path still works but gives a poor 200-line window.
CROSS-CAPTURE MATCH (2026-09-15 after reboot): tested two real swipes of one finger. Root cause found:
horizontal ridge period consistent (~10-12px) but vertical (swipe) period 62-116px and INCONSISTENT
(speed oversampling). Added isotropic_v() to vfs495_capture (resample swipe axis to match horiz spacing)
-> cross-capture bozorth3 score 0 -> 18/40 (threshold 40; diff fingers still ~0, so discriminating).
STILL UNDER THRESHOLD: swipes capture too little finger -> isotropic images only 80-190 rows (few minutiae).
NEXT to make login work: (a) capture fuller/slower swipes + better local motion compensation in reconstruct;
OR (b) BEST: use proprietary libvfsFprintWrapper.so assembly (usr/lib64/ in the rpm) for match-quality
images (what vcsFPService/rindeal use) instead of our reconstruct.py. Then wire fprintd via
FP_VIRTUAL_IMAGE + bridge (WRAPPER.md).

## fprintd + PAM setup written (2026-09-15) -> SETUP_FPRINTD.md
Distro libfprint 1.94.9 HAS virtual_image (verified) -> stock fprintd works, no custom lib needed for login.
Setup: apt install fprintd libpam-fprintd; systemd drop-in sets FP_VIRTUAL_IMAGE=/run/fprint/virtimg_sock on
fprintd; run tools/vfs495_bridge.py as a root service (capture loop -> feeds socket); fprintd-enroll;
pam-auth-update to enable pam_fprintd (sufficient, password still works). Bridge uses vfs495_capture_asm.py
(the assembled/match-quality capture). Caveats documented: root+gdb capture, heavy idle loop, sensor needs
reboot if stuck, password fallback always works.

## *** SETUP EXECUTED & WORKING (2026-09-15) ***
- Installed fprintd 1.94.5 + libpam-fprintd; fprintd drop-in /etc/systemd/system/fprintd.service.d/
  virtimg.conf sets FP_VIRTUAL_IMAGE=/run/fprint/virtimg_sock. fprintd sees the virtual_image device.
- vfs495-bridge.service (root, enabled+active) runs tools/vfs495_bridge.py -> vfs495_capture_asm.py.
- ENROLLED right-index via `fprintd-enroll` (5 stages, real swipes). `fprintd-verify` -> verify-match
  (confirmed twice, incl. with the systemd service). PAM: pam-auth-update enabled fprintd in
  /etc/pam.d/common-auth (pam_fprintd max-tries=3 timeout=30, success=2; pam_unix password fallback).
- Removed /etc/sudoers.d/claude-code (NOPASSWD revoked) -> sudo now uses fingerprint/password via PAM.
- To use: `sudo -k && sudo true` then swipe; or lock screen / login. Password always works as fallback.
- Undo: pam-auth-update (untick fprintd); systemctl disable --now vfs495-bridge; rm the drop-in + unit.

## NEXT SESSION START HERE

## NEXT SESSION START HERE
1. Finish frame decode: read irDliRTFalconData fully; derive exact (type,width,nlines,trailer) layout.
2. Write tools/reconstruct.py: demux main image frames from ep2, motion-stitch, output PGM.
3. Validate against a fresh clean swipe; then scaffold a libfprint 1.94 driver (vfs495) modeled on vfs301.
Feasibility is PROVEN: end-to-end plaintext fingerprint capture works on Debian 13 via our own path.

## Open questions
1. Is the .img decrypted on host (key in binary) before upload, or uploaded encrypted?
2. Is the capture data path (irDliGetImage) AES-secured on VFS495, or only matching/auth patches?
3. Minimal command sequence: device init -> patch upload? -> calibration -> capture.
