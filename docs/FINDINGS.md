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
- To use: `sudo -k && sudo true` then swipe; or lock screen / login. Password always works as fallback.
- Undo: pam-auth-update (untick fprintd); systemctl disable --now vfs495-bridge; rm the drop-in + unit.

## Sensor events + SSL re-test on a second machine (2026-10-09, HP laptop, NixOS)
Sensor events (idsSensorEventPerformCallback @0x459bf0, event id in esi), timeline of one getprintwait:
- 0xcc ~1.6 s after start = wake-on-event armed; then NOTHING runs while idle (no scan lines stream).
- 0xd0 = finger detected (the swipe starts) -> lines stream, IRprocessScanline etc.
- 0xcd = finger gone / swipe done, 0xd2 = capture finished.
UnpackLineRT is NOT a finger signal: it fires 3x at ~1.5 s during init (calibration lines), no finger.
The bridge now uses 0xd0 to report finger-on to fprintd (harvest_assembled.py, VFS_FINGER_SOCK).
The ~2 s "arm" delay per capture = gdb/process start + patches + SPI reads + SSL handshake + calibration
(armed at 1.63 s after `run`); paid on every capture because the session is not reused.

SSL re-test with a USB trace of HP's own run (runtime/usblog.c, no gdb -> real timing):
- HP's ServerHello -> flight gap is 4.7 ms; the sensor then needs ~260 ms (its RSA decrypt) before
  answering CCS+Finished. tools/ssl_session.py: 3.7 ms gap, and the alert 0x2f also comes ~256 ms after
  the flight -> the sensor decrypts our CKE and fails at the Finished check. TIMING RULED OUT.
- HP adapts init to the sensor state: if GetVersion shows a patch still loaded (previous run), it sends
  1a UnloadPatch first and the first 06 patch reply is 0000 + 32 extra bytes; on a clean sensor it skips
  1a and the reply is plain 0000. HP's handshake succeeds from the clean state too, so neither matters.
- Exact replay of HP's clean-state run (same commands, same replies, same inter-command pauses incl.
  12 ms before the 2nd 1f and 23 ms before the 1301 B patch) still -> 0x2f. Wire + timing identical.
- The 693 B and 1301 B patches are byte-identical across runs (static, no per-session data) and have
  entropy 7.7-7.9 bit/byte -> uploaded encrypted; the sensor-side SSL code is not readable from them.
  (Answers open question 1: the patch reaches the sensor encrypted.)
- After a fatal alert the sensor resets itself (USB re-enumerates); harmless, comes back clean.
- NEW: the sensor KEEPS HP's SSL session after HP's process is killed: a plaintext 01 sent afterwards is
  answered with an ENCRYPTED alert record (15 03 00 00 20 + 32 B), then the sensor resets. This is why
  "priming with the tool first" never helped, and it allows a session-takeover path: let HP handshake
  once, dump its key block / IVs / sequence numbers via gdb, continue the session from our own code.
*** SSL HANDSHAKE SOLVED (2026-10-09): 0x2f was the WRONG RSA KEY ***
- Differential test: one HP handshake under gdb (premaster, EM incl. PKCS#1 padding, randoms, master,
  keyblock, every handshake-hash update) + its real flight from the USB log; rebuilt the flight offline
  with ssl_session.py from HP's own inputs. Everything matched byte-exact (master, keyblock, 368 B hash
  input, CCS, 69 B encrypted Finished) EXCEPT the RSA ciphertext.
- HP sets up TWO RSA-2048 keys per session at 0x51fac0 (bits=rdi, exp=rsi, modulus=rdx). The FIRST one
  (what runtime/dump_rsakey.py dumps: it stops at the first hit) is NOT used for the key exchange
  (probably the root key that validates the sensor certificate). The SECOND one is the session key:
  with it, pow(EM_be, 65537, n_le) == wire ciphertext exactly (modulus little-endian, EM and output
  big-endian, as documented). The second key is per-device but stable across sessions and sensor resets.
- With the second key, ssl_session.py completes the handshake: the sensor answers CCS + Finished
  (+ an AppData record 17 03 00 00 40 ...). No HP binary in the loop. The earlier "content-independent
  0x2f" was the sensor decrypting garbage with every CKE we sent.
- The session key does not need HP or a dump: it is storage id 10 in the 4 KiB flash block that init
  already reads (1f05 -> ep 0x82; block = flash 0x1000..0x1fff). Layout: 'EAT"' header, then from byte 13
  entries `ff <id> <u32 addr LE> <u32 size LE>`; id 10 = addr 0x16b6, size 0x100 (ids 7,8,11-15 also there).
- Sensor Finished quirk: label 'SRVR' (LE int 0x53525652) over the SAME handshake msgs as the client
  Finished (ClientHello + ServerHello/Done + CKE). The client Finished is NOT hashed in (standard SSLv3
  would include it).
- Verified end-to-end from our own client (no HP code running): handshake OK, sensor Finished VERIFIED,
  every record MAC ok, and an encrypted GetVersion (AppData record `17 03 00 ..` holding `01`) is answered
  with a valid encrypted 38 B reply (patch bits set, as after HP's init).

Session lifecycle (verified 2026-10-09):
- Close = encrypted alert record (type 0x15) with plaintext `01 00` (close_notify), exactly what HP sends
  on a normal exit; the sensor answers with its own encrypted `01 00`. tools/ssl_session.py close_session().
- After a clean close the sensor keeps the firmware patches loaded (GetVersion byte 17 != 0). Like HP, send
  1a UnloadPatch before re-uploading them; then a new session opens immediately (back-to-back runs, no reset).
- Without a close (process killed / crashed) the sensor keeps the session: the next plaintext command gets an
  encrypted alert and the sensor resets itself (re-enumerates, new USB address, can take >3 s). If it hangs
  instead (writes time out), a logical unplug clears it: echo 0 > /sys/bus/usb/devices/<port>/authorized,
  then 1. No power-off needed for this case.
- Replies can be longer than 1 KiB (some 02 commands return ~2.4 KiB): read up to 16 KiB; the sensor ends a
  reply with a short packet. A truncated read leaves the sensor hung.
- The finger stream on ep 0x82 during a swipe (after 17 reports finger) is ENCRYPTED (flat byte histogram),
  separately from the SSL session. SOLVED (2026-10-09): the HOST picks the image key. The arming command
  (02, 3033 B = the last setup command) carries a 32-byte AES-256 key at offset 0x6ef (2927) and a 16-byte
  IV at 0x70f (2959); the command itself travels inside the SSL session. The sensor encrypts the whole swipe
  as ONE AES-256-CBC stream with that key/IV (verified: matches HP's palAesCBCDecrypt output byte-exact, and
  CBC-decrypting our own swipe with the key we sent yields clean 01fe frames). Decrypted stream = N frames of
  272 B: 8 B header (01 fe xx 00 07 07 ..) + 264 pixels. HP decrypts a whole ~84096 B decoder buffer at once.
- FULL CAPTURE WITHOUT HP (2026-10-09): our own client ran init + handshake + the 24 setup/calibration
  commands + finger poll + read the encrypted swipe + decrypt (host key) + descramble (driver table) +
  reconstruct.py -> a recognizable fingerprint (loop core, ridge flow). A FRESH random key/IV from our own
  client (secrets.token_bytes, patched into the arming command) works: the swipe decrypts into clean frames,
  so the sensor does not check or derive the key. Remaining: detect swipe end by line energy instead of a fixed read window; better image
  assembly (reconstruct.py is weaker than HP's motion-compensated IRreconstructImage).

ssl_session.py bugs found (not the cause of 0x2f): (1) the 1f flash reads request 16384 B, but the sensor
sends exactly 128 / 4096 B in full 64 B packets with no short packet, so each read times out (400 ms) and
the data is lost; read exactly 128 / 4096 like HP. (2) Commands go out back-to-back; without HP's ~12 ms
pause before the second 1f the sensor reset during init.

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

## HP image assembly: how vertical height works (2026-10-10, static analysis of IRreconstructImage)
The VFS495 is a swipe sensor; output height depends on finger speed. HP's assembly (no in-process reuse
is possible: validity-sensor is ET_EXEC, not a PIE, so it cannot be dlopen'd, and IRreconstructImage
references ~7 globals + stateful circular buffers set up during capture). The ALGORITHM, from the binary:
- A second short sensor row (decrypted frame columns 200..263, "aux") sits ~4.3 px from the main row and
  lines up with main columns ~70..133. Each ridge crosses aux `lag` lines before main, so finger speed =
  D_ROWS / lag px per scan line. HP estimates lag per line during capture (IRcorrelate / IRcorrelateUp /
  IRcorrelateDown for swipe direction).
- IRfinalizeYlagEstimates cleans the per-line lag BEFORE reconstruction: interpolateYlags (gap fill),
  detectStictionZone (finger paused -> no travel), detectNoiseBeforeBase (ignore pre-contact noise),
  opt_med5 (5-point median). This is the stabilization our prototypes lacked.
- IRreconstructImage accumulates displacement and emits output rows at a FIXED displacement->row rate
  (fixed divisor, not adaptive), each row built by IRinterpolateLine (linear interp between adjacent input
  lines), and CAPS the output at 300 rows (loop guard `cmp [rsp+0x94],0x12c; ja` = 300; a short swipe
  gives fewer, e.g. the 267-row capture). Also: IRfinalizeXlagEstimates + IRapplyXLagOffset correct
  sideways drift; IRSkewCorrectImage corrects skew; IRConstrastEnhanceImageRows/Cols; IRhandleInvertAndFlip
  mirrors (HP's output is L-R mirrored vs our raw column order).
TAKEAWAY for a native reimpl: the fix for inconsistent height is a FIXED pixels-per-displacement rate
(from the aux-row lag) + a 300-row cap, NOT reconstruct.py's adaptive out_rows (which gave 200..1200) and
NOT frequency-domain rescaling (tried twice, fails on anisotropic real prints). tools/vfs495_assemble.py
(scratch prototype) had the right shape (fixed rate `d` from the aux lag, ~24 mean self-score) but a noisy
lag estimate; porting HP's median+stiction cleanup of the lag is the missing piece.

## Static patch extraction is a dead end (2026-10-10) — one-time HP run stays necessary for setup
Goal was to build captures/init_cmds.json + capture_cmds.json from HP's downloaded package files WITHOUT
running HP's binary, so the native path needs no HP execution at all. Result: not feasible, low value.
- init patch #1 (693 B) IS stored verbatim in validity-sensor (@0x172080) — copyable.
- The other patches (1301/2581/405 B and the 02 capture-config blobs) are stored in the binary too, but the
  uploaded form differs: HP replaces a leading 4 B header + 256 B RSA signature with a 32 B authenticator
  (scsReplaseRSASignatureByHMAC @0x516f60), AND the body bytes differ from the stored body (stored_body !=
  sent body) -> the patch is re-keyed/encrypted per sensor at runtime, not merely re-signed.
- The 32 B authenticator uses K = SHA256(storage id 10 key = the 256 B RSA modulus from sensor flash), then
  a chain of 32->32 B SHA calls with per-block counters (12 palCryptoDigest calls per sign). It is NOT a
  plain HMAC-SHA over the body (all standard constructions tried, none match). This is HP's firmware-patch
  protection tied to the sensor key.
- Conclusion: reproducing the uploaded patches = reimplementing HP's patch encrypt/authenticate scheme, for
  the sole benefit of skipping ONE HP run at setup. Not worth it, and it is the sensor's protection
  mechanism. Keep the community approach: user downloads HP's package, runtime/trace_to_init.py captures the
  init+setup blobs from ONE traced HP run; after that HP never runs again (native session/capture/decrypt).

## HP-style assembly reimplemented + validated against HP's own images (2026-10-10) -> tools/vfs495_assemble.py
Method: 6 swipes through HP's binary under gdb, saving per swipe BOTH the decrypted frames (irDliRTFalconData)
and HP's assembled image (IRqualityDetermination). Our assembly runs on HP's exact input; scored with
vfs495-match (fprintd's NBIS matcher). Monotone DP alignment of every HP output row to its source input line
recovered HP's real row<->line mapping (ground truth for the lag), orientation and polarity.

| pipeline (same 6 swipes)                                  | vs HP images (30 pairs) | ours vs ours (15) |
|-----------------------------------------------------------|-------------------------|-------------------|
| HP vs HP                                                   | 77.7 (15/15 >= 40)      |                   |
| old native path (reconstruct.py)                           | 2.5  (0/30)             | 15.7 (1/15)       |
| HP's own row mapping ("oracle") + our band-passed pixels   | 26.3 (5/30)             | 28.1              |
| oracle mapping + raw pixels, inverted, column stretch      | 42.7 (15/30)            | 32.7              |
| **vfs495_assemble.py** (own lag, Viterbi penalty 0.01)     | **50.5 (18/30)**        | **48.8 (6/15)**   |
| same, lag penalty 0.002 / 0.005 / 0.02 / 0.05              | 35.0 / 36.0 / 44.5 / 36.0 | 37 / 44 / 46 / 39 |
| same, constant lag per swipe                               | 23.5                    | 19.0              |
| same, ref lag 7 / 9 instead of 8                           | 42.3 / 22.5             | 41.7 / 42.5       |

What mattered (corrections to the section above):
- Lag scale: real aux->main lags are 50..170 LINES (not ~4 px worth); HP's "8 lines = 1 output row" holds in raw
  line units (~10 input lines per output row; ref 8 beats 7 and 9). Not a fixed divisor of a pixel speed.
- Lag cleanup: greedy per-line tracking (HP's prev-8..prev+7 search) slid into a spurious lag ~3 minimum on our
  data. A Viterbi path over windowed (48-line) correlation with a cost per unit of lag change is the working
  stand-in for HP's gap-interp + med5 + stable-segment cleanup. Speed variation within a swipe is real
  (constant lag scores 23).
- Swipe span: HP uses the faint tail of the swipe (~1000-1500 lines past our old energy cut); end threshold
  10% of peak energy. Output = first 300 rows from contact (HP: 5/6 swipes exactly 300 rows).
- Pixels: HP keeps raw sensor values (pores, ridge shape). Band-passed/locally normalized rows lose most
  minutiae for NBIS. Polarity is INVERTED vs raw; L-R mirrored; NOT vertically flipped (time runs top->bottom).
  Column percentile stretch (1/94) = HP's IRConstrastEnhanceImageCols; baseline subtraction adds nothing on top.
- Sideways drift (xlag/skew): HP's rows are not shifted vs their source lines on these swipes (the +-5 px
  "shifts" were half a ridge period = the polarity inversion). Not implemented; no measurable need.
Remaining gap to HP (50 vs 78): lag estimate (oracle mapping alone is not the ceiling, HP's analog
reconstruction not ported). vfs495_native_capture.py's quiet end-rule was lowered to 10% of peak so the tail
the assembly needs is not cut off.

Live test (native capture, no HP binary, same day): 3 swipes scored 24 / 7 / 4. One swipe was mostly vertical
streaks: the finger RESTED on the sensor before moving, and every resting line still emitted rows. HP's
detectStictionZone case; none of the 6 HP swipes had a pause, so offline validation could not see it.
Fix (vfs495_assemble.moving): similarity of a line with the line 64 earlier is ~0.83-0.95 while the finger
rests (and before contact), < 0.5 while it moves; lines above 0.75 advance 0 rows, their lag windows are
ignored, and the image starts at the first moving line. 6 new live swipes (2 with a deliberate ~1 s rest):
all six give clean prints; one-to-one scores mean 39.4, 7/15 >= 40 (best 73), the two rest-first swipes
score like the others. (The stiction step was tuned on live data only; the offline HP comparison above was
done before it, with those recordings already deleted.)

## What the per-device setup data actually is (2026-10-10) — corrects the "static patch extraction" note above
Classified the 8 init + 24 setup commands by opcode, and diffed two independent HP runs on the same sensor
(scratch hp_plain_run1/2.json, decrypted). The earlier note's "patches re-keyed/encrypted per run" was wrong:
the firmware patches are STABLE per sensor (byte-identical across runs); only tiny nonce fields in the config
vary. Breakdown of the setup stream:

- **`06` DownloadPatch — HP's firmware, the only irreducibly-proprietary part.** 4 distinct patches total
  (693 B init; 1301 B init+setup; 405 B setup x3; 2581 B setup), ~5 KB distinct. Byte-identical run-to-run on
  this sensor. They differ from the copies stored in validity-sensor (re-keyed/authenticated for this sensor
  via scsReplaseRSASignatureByHMAC + a SHA chain over storage-id-10 key), so they can't be lifted from HP's
  package, only captured from the running sensor. This is firmware code-signing/DRM tied to the device key;
  reproducing the transform (stored patch -> uploaded patch) = forging firmware auth, which we do NOT do. It
  is also moot: the sensor needs HP's firmware to work at all, like any linux-firmware blob.
- **`02` config — structured parameters, NOT signed, NOT opaque.** 12 commands, 31.6 KB, but ~97-99 % CONSTANT
  run-to-run. Only small embedded fields change: 1 byte ([11][12][13][14]), a 64 B block ([4] @2225, [18][23]
  @2585), and the arming command ([23*]/3033 B) whose 32 B key @2927 + 16 B IV @2959 the HOST chooses anyway.
  These are config/calibration tables the sensor accepts on replay (the native path replays them verbatim and
  works). Understandable protocol, not a secret — could be synthesized, but see below.
- **`1a` UnloadPatch (x5), `1f` SPI flash read (x1), `12` (x1), `17` GetFingerState poll** — trivial fixed cmds.

**Bottom line for "no proprietary blobs":** the irreducible proprietary core is the 4 firmware patches (~5 KB),
and there is no way around shipping/uploading HP's firmware — that firmware IS what runs the sensor, and it is
authenticated to the device. Synthesizing the `02` config ourselves would remove ~31 KB of captured data but
still leave the `06` patches, so it is a lot of work for a cosmetic win. The practical minimal-proprietary
setup already stands: capture the patches + config once from the user's own sensor, replay forever, never run
HP again. Analogous to needing linux-firmware for wifi/GPU. (vfs495_native_capture.py / the libfprint driver.)

## Which HP patches does the sensor need? Live probes (2026-10-10) -> tools/probe_patches.py
Question: can setup.bin be made without running HP's binary (or without any HP file)? Probed on the sensor with
subsets of the recorded commands (RAM only, nothing written to flash). Variants: A = no patches at all,
B = only the 693 B init patch (stored verbatim in validity-sensor), C = both init patches, setup without its
06/1a, D = no init patches, setup as recorded.

| run | sensor state before | variant | result |
|-----|---------------------|---------|--------|
| 1 | patches loaded by the driver, unloaded with 1a | A | session opened; setup stops at the 2691 B config (`5004`), the 2666 B one returns no data; sensor reset right after |
| 1 | after that reset | C | session ok (GetVersion patch byte 07); same stop as A |
| 2 | after C, patches unloaded | D | ClientHello tunnel refused in plaintext: `2b04` |
| 2 | | B | `2b04` |
| 3 | | A | `2b04` |
| 3 | sensor resetting (delayed, after the 2b04) | C, A | I/O error / timeout: inconclusive |
| 4 | forced reset (R), back 1.2 s before | A, E | init timed out (sensor not ready yet?): inconclusive |
| 4 | clean (patch byte 00) | C | same as run 1: 2666 B no data, 2691 B `5004`; no reset afterwards (20 s) |
| 4 | after C's clean close, 1a, no reset | A | `2b04`: the leftover theory is wrong |
| 4 | after that 2b04, no reset for 20 s | F | I/O error on first access, then the sensor reset: inconclusive |
| 4 | clean | G (no 405 B) | **every config accepted**, 2666 B returns its data; armed; no finger seen |
| 4 | | H (no 1301 B reload) | every config accepted; armed; no finger seen (swipe missed) |
| 5 | forced reset, 5 s wait | A, E | init times out at the 4 KiB flash read (`1f05`); never reached the handshake |
| 5 | forced reset | F | session ok, then I/O error uploading the 405 B patch; sensor reset |
| 5 | forced reset | G (no 405 B) | **capture works**: finger detected, 8283 lines streamed (not decoded) |
| 5 | after G's clean close | H (no 1301 B reload) | **capture works**: 4647 lines streamed (not decoded) |
| 6 | forced reset | A | `1f05` **rejected `6d04`** (no data); handshake with an earlier step's key refused **`2604`** (not `2b04`) |
| 6 | forced reset | E (1301 B only) | `1f05` rejected `6d04`; the **1301 B upload kills the sensor** (I/O error, reset) |
| 6 | forced reset | F | again I/O error uploading the 405 B patch (2/2, both right after a failed E) |
| 6 | forced reset | H | capture works, decoded: 5196 lines -> 200x300 print |
| 6 | forced reset | G (no 405 B) | capture works, decoded: 4590 lines -> 200x300 print (not yet scored) |
| 7 | forced reset (no A/E before) | F | I/O error uploading the 405 B patch again (3/3) |
| 7 | forced reset | H, 5 swipes | 5/5 prints; NBIS among them: 8/20 pairs >= 40 (swipe 3 matches none) |
| 7 | forced reset | G, 5 swipes | **finger never detected** in 5 swipes (the user swiped); no print |
| 8 | forced reset | F (traced) | 405 B upload #1 fine; 2666 B config's data read times out (3 s); `12`, `1a`, then the **write** of 405 B upload #2 fails (I/O error) |
| 8 | forced reset | G, 3 swipes | finger detected 3/3, 3 prints |
| 8 | forced reset | H, 3 swipes | finger detected 3/3, 3 prints |
| 8 | forced reset | G, 3 swipes | no finger in 15 s (user swiped), then 2 partial swipes (1300 / 1553 lines) |

Findings:
- **The session needs HP's 1301 B security patch.** On a sensor without a patched session, the ROM refuses
  the 0x11 handshake tunnel (`2b04`, plaintext status, no alert), 3/3 times. The 693 B patch alone doesn't help.
  So the earlier assumption "the session is a ROM feature" is wrong; it comes with HP's security patch.
- Run 1's A success is NOT leftover state from a clean close + `1a`: run 4's C A (exactly that) got `2b04`.
  Unexplained; run 1 came after the driver's full setup (with the 405 / 2581 B patches), not after C.
- **Setup needs the setup patches** (405 B x3, 2581 B, 1301 B): without them, the config commands up to the
  2625 B one are accepted and return their calibration data, the 2666 B one returns none, and the 2691 B
  one is rejected (`5004`). Both init patches present (C) or not (A) makes no difference there.
- After a refused handshake (`2b04`) the sensor does NOT reset by itself (run 4: none within 20 s). It stays
  broken until the next access, which gets an I/O error and makes it reset. Run 3's "delayed reset" was that.
  Force a reset after a 2b04 (the probe now does). After a forced reset, the first init timed out twice
  although the sensor was back on the bus 1.2 s earlier: wait longer (the probe now waits 5 s).
- **The 2581 B patch is what the 2666 B and 2691 B configs need** (run 4 G): without any 405 B patch, all
  configs are accepted and the 2666 B one returns its data. See the next section for the TLV types.
- **A capture works without the 405 B patch** (run 5 G: 693 + 1301 B at init, 2581 + 1301 B in setup) and
  without HP's 1301 B reload (H). Not yet checked: that G's stream decodes into a print as good as the full
  setup's (the probe now decrypts and assembles it).
- **The 693 B patch is the bootstrap.** On a freshly reset sensor without it, the ROM rejects the 4 KiB flash
  read (`1f05` -> `6d04`, the read that holds the RSA key), refuses the handshake even with a known key
  (`2604`), and an upload of the 1301 B patch makes the sensor fail and reset (run 6 A, E). After a session with
  it plus `1a`, the read works without it (run 4 A). Fits the headers: 693 B is the one patch with an RSA
  signature (ROM-verifiable); the others carry the 32 B per-sensor authenticator, which the 693 B code
  presumably checks. So 693 B -> 1301 B -> 2581 B is a dependency chain, not three independent features.
- F's failure is not about the 405 B patch (run 8 trace): the first 405 B upload works. Without the 2581 B
  patch the 2666 B config returns its status but no data (as in C), and after that the sensor is in a bad
  state: the next patch upload's USB write fails and the sensor resets. ("last command" pointed at the first
  405 B upload in runs 5-7 only because both records have the same size.)
- **Without the 405 B patch, finger detection is unreliable and prints are worse.** G found the finger in 7 of
  13 prompts over runs 5-8 (H: 11/11 in runs 7-8); the user swiped every time. NBIS, probe prints of one
  finger (partial swipes and the < 80-row one left out; probe-H-1791663402 / -1791664001 left out, they come
  from runs not in this table):

  | pairs | mean | >= 40 |
  |-------|------|-------|
  | H vs H (8 prints) | 32.9 | 21/56 |
  | G vs H (3 x 8)    | 28.7 | 6/48  |
  | G vs G (3 prints) | 20.9 | 0/6   |

  The finger poll looks the same with and without it (`00..` then `0000 02..`). So the 405 B patch is not
  needed for the configs or the stream, but for the sensor to work well; it's loaded right before the
  calibration configs (2331 B, 2691 B), so probably calibration / detection. It stays in setup.bin.
- Probe prints score lower than the driver's (H: 8/20 pairs >= 40 vs the driver's 73/90): rushed swipes in a
  15 s window and no fast-swipe gate. Compare G against H from the same probe, not against the driver.

Consequence: a setup.bin without HP's binary would need the transformed patches, i.e. HP's per-sensor patch
authentication (see "Static patch extraction is a dead end"), which this project keeps out of scope. The
one-time vfs495-setup run stays.

Next step (open): **understand what the security patches do**: what the 1301 B patch adds (the session,
key handling), what the 405 B / 2581 B setup patches enable (which config fields and sensor modes need them),
and why the 2666 B / 2691 B configs depend on them. That could show whether the sensor's ROM offers another
way to capture, or which patch is the real minimum. It is protocol and behaviour work on the sensor;
reproducing the patch authentication stays out of scope.

## What the patches and configs look like on the wire (2026-10-10, offline, T6) -> tools/probe_patches.py
From the recorded commands only (captures/*.json), no HP binary.
- **`06` patch header:** `06 | 02 00 | u16le auth length | auth | body`. The 693 B patch carries a 256 B
  auth (the RSA signature: this is the copy stored verbatim in validity-sensor). The 405 / 1301 / 2581 B patches
  carry 32 B (HP's per-sensor authenticator, see "Static patch extraction is a dead end"). Bodies 368 / 432 /
  1264 / 2544 B, entropy 7.3-7.9 bit/byte: encrypted. Their content can't be read, so what each patch does
  can only be learned from the sensor's behaviour.
- **`02` config = 5 B header + TLV list** (u16le type, u16le length, payload). All 12 recorded configs parse
  exactly to their end. Type 3 (9 B) = register write `u32le addr, u32le value, u8 width` (60-82 per config,
  60 distinct addresses 0x30042000..0x38000014); type 2 (1408 B) is in every config (6 variants), probably the
  timeslot table.
- **Type 6 (106 B) = the stream crypto block:** 96 B random + fixed `..0003 0000 0401`. The image key and IV
  of the arming command (offsets 2927 / 2959) are its first 48 B. The calibration configs (2331 B, both
  2691 B) have one too, with the first 64 B random; the arming config randomizes all 96 B (the driver
  replaces only key + IV, the other 48 B stay as recorded and work).
- **TLV types vs the patch HP loads right before the config:**

  | config (setup #) | patch before | TLV types beyond 2/3/10/21 | without setup patches (run 1) |
  |------------------|--------------|----------------------------|-------------------------------|
  | 2331 B (3)       | 405 B        | 6                          | accepted, data returned        |
  | 2711-2625 B (6-12) | 2581 B     | 5, 12-18 (calibration scans) | accepted, data returned      |
  | 2666 B (13)      | (2581 B)     | 5, 7, 12, 17, **19, 20, 29** | accepted, **no data**        |
  | 2691 B (17, 22)  | 405 B        | 5, 6, **23, 27**           | **rejected 5004**              |
  | 3033 B (23, arming) | 405 B     | 5, 6, 23, 27, **24** (338 B) | never reached                |

  So the ROM handles types 5, 6 and 12-18; the first types it doesn't are 19/20/29/7 and 23/27. Run 4's G
  (no 405 B patch, 2581 B loaded) accepted all of them incl. the arming config's type 24: **the 2581 B patch
  adds 19/20/29/7 and 23/27** (or makes the ROM accept them). The 1301 B patch adds the session. What the
  405 B patch is not needed for any config to be accepted, but without it finger detection is unreliable and
  prints match worse (run 8): probably calibration.

**Patch roles (behaviour, runs 1-8; one sensor):**

| patch | auth | needed for | without it |
|-------|------|------------|------------|
| 693 B | RSA signature | everything: 4 KiB flash read (RSA key), handshake, loading the other patches | `1f05` -> `6d04`, handshake `2604`, 1301 B upload kills the sensor |
| 1301 B | 32 B per-sensor | the SSL session | handshake refused `2b04` |
| 2581 B | 32 B per-sensor | config TLV types 19/20/29/7 (2666 B) and 23/27 (2691 B, arming) | 2666 B gives no data, 2691 B `5004`; the sensor then fails on the next patch write |
| 405 B | 32 B per-sensor | reliable finger detection, print quality (calibration?) | ~half the swipes undetected, prints match worse |

HP's 1301 B reload during setup isn't needed (H works the same). The minimum stays all four patches. The register writes don't explain it: configs 13/17/23 write no address
  the ROM-accepted configs don't, only 15-16 different values.
- **The session survives an unload:** HP's own setup sends `1a` after the 1301 B reload and then loads only the
  405 B patch, and the session carries on through arming and capture. So once the handshake is done, the
  session doesn't need the 1301 B code resident. That fits run 1's A (a new handshake right after an unload,
  no reset): the 1301 B patch probably leaves something behind that only a reset clears.

Probe extensions to test this (`tools/probe_patches.py`, `--plan` prints each step without the sensor):
R forces a clean sensor (stale session -> alert -> reset, waits for the re-enumeration); E = only the 1301 B
patch; F / G / H = setup without the 2581 B patch / the 405 B patches / the 1301 B reload; T = no setup
patches, but the 2691 / 3033 B configs without TLV types 23 and 27. Run 4 used `R A R E C A F G H`; run 5-6 used `R A R E R F R H R G`; after run 6 the default is `R F R H R G`. Probe
hygiene: every step waits for a running reset instead of a fixed 3 s, plus 5 s after a re-enumeration; refusals,
errors and rejections watch for a reset and force one if none comes (a 2b04 leaves the sensor broken).

## T7 run 9: G vs H in detail, ROM-only configs, plaintext (2026-10-10) -> VFS495_PROBE_DUMP, tools/compare_probe_dumps.py
`R G R H R G R H` with 3 swipes each and full dumps, then `R U R V R W R P`. One sensor, one finger.

**The 405 B patch makes no measurable difference in this run** (contradicts run 8's G result):
- Finger detected 6/6 in G (and 6/6 in H), after 1.1-2.4 s in both. First poll reply after arming is
  `00000053094000` or `000000d3094000` in both G and H (not tied to the patch).
- Calibration reads after the plaintext configs (2711-2666 B): G-vs-H byte differences are exactly as large
  as G-vs-G and H-vs-H (e.g. 2503 B config: mean |diff| 6.3 in every pair). Run-to-run noise, no offset.
- The 2402 B reply after the 2691 B / arming configs: 9-10 bytes vary between runs (offsets 1410-1412,
  1980-2134), as much within a variant as between. One byte separates them: **offset 1546 of the arming reply
  is `01` in both G runs, `00` in both H runs** (2 runs each; meaning unknown).
- The 2691 B calibration reads decrypt with the config's type-6 key: 20 `01fe` frames, column means equal in G
  and H. (The 288 B read after the 2331 B config decrypts to no `01fe` frames.)
- Swipes, per-column: baseline 133.2 vs 133.2 (column correlation 0.99), contrast 40.7 vs 41.2, noise 5.5 vs 5.4,
  ridge energy 19.6 vs 19.7.
- NBIS (prints assembled from the dumps with tools/vfs495_assemble.py, vfs495-match):

  | pairs | mean | >= 40 |
  |-------|------|-------|
  | H vs H (6 prints) | 55.6 | 16/30 |
  | G vs H            | 54.9 | 44/72 |
  | G vs G (6 prints) | 48.1 | 14/30 |

  G vs G a bit lower, within what 6 prints can show. Run 8's 0/6 and "~half the swipes undetected" were most
  likely swipe variance in rushed 15 s windows. Needs the driver measurement (10+ swipes) before the 405 B
  patch is dropped.

**ROM-only configs (no 2581 B patch):**
- U (2666 B config without 19/20/29/7, 2691 / 3033 B without 23/27): the stripped 2666 B config (2572 B) is
  accepted but returns no data, `12` and `1a` pass, then the next patch upload fails (as in F). Same for W.
  So the 2666 B config breaks the data path without the 2581 B patch, with or without its unknown types.
- **V (U without the 2666 B config): capture works.** All configs accepted, finger detected, 3206 lines, a
  200x300 print; baseline / contrast / noise like H; NBIS vs G/H prints 14/24 pairs >= 40, mean 53 (1 print).
- Without types 23/27 the 2691 B / arming configs return no 2402 B reply (`0000` only): that reply belongs to
  23/27.

**Bare ROM, plaintext (P):** no patches, no session: the first plaintext `02` (2331 B) is refused with `0404`,
like plaintext commands on a patched sensor. No plaintext capture path.

Next: step M (only the init patches 693 + 1301 B; setup without any patch, without the 2666 B config, 23/27
stripped) combines G and V. If it captures as well, the driver could do the same with a reduced setup.bin;
measure that with the driver (hw_test.sh capture + vfs495-match, 10+ swipes) before changing anything.

## T7 run 10: step M, no setup patches at all (2026-10-10)
The run was `R M R H R M R H R M R H R M R V` (4 x M, 3 x H, 1 x V), 3 swipes each, dumps. **M = init patches only
(693 + 1301 B); setup without any 06 / 1a, without the 2666 B config, 2691 / 3033 B configs without types 23/27.**
- **M captures.** Every config accepted, every swipe detected and streamed (9/9 with the user swiping), 200x300
  prints. The runs without a finger (one M, one H, and an H stopped after 4 polls) were unattended starts:
  the user didn't swipe. In the attended run (R M R H R M R V) all 12 prompts were detected in 0.9-5.0 s.
- Ridge energy M 15.7 vs H 15.6 (same session); baseline / noise equal.
- **Types 23/27 cause the first poll reply** `00000053094000` / `000000d3094000`: M and V (without 23/27) always start
  at `00000000000000`; G and H (with them) always start with one of the two. Plus the 2402 B reply (run 9).
- NBIS over runs 9-10 (prints assembled from the dumps; vfs495-match; libfprint's virtual-device overheat
  guard stops a run after ~460 comparisons, so it was scored in batches):

  | pairs | mean | >= 40 |
  |-------|------|-------|
  | H vs H (9 prints) | 54.4 | 43/72 (60 %) |
  | G vs H            | 57.2 | 69/108 (64 %) |
  | G vs M            | 51.4 | 56 % |
  | H vs M            | 49.9 | 87/162 (54 %) |
  | V vs V (4 prints) | 49.9 | 50 % |
  | G vs G (6 prints) | 48.1 | 47 % |
  | M vs M (9 prints) | 44.5 | 47 % |

  M matches H prints (cross-scores ~50), so it's the same image. Its self-scores are ~10 lower than H's. That's
  a possible small quality cost of dropping 23/27 / the 2666 B config / the 405 B patch, or just swipe variance
  (G vs G is as low). Probe swipes can't settle it; the driver measurement (10+ swipes each) can.

**Candidate minimum: the two init patches (693 + 1301 B), no setup patches.** That leaves 2 of the 4 HP patches
(~2 KB instead of ~5 KB) and drops the 2581 B and 405 B patches from setup.bin. To test it with the driver: the
driver writes the image key at the fixed offsets 2927 / 2959 (`VFS495_ARM_KEY_OFF`). That's wrong for a stripped
arming config (3013 B); it must find the type-6 block instead (as probe_patches.set_key6 does).
Done: the setup parser locates it (`vfs495_config_key_offset`, 2907 in the minimal file), and
`make_setup_bin.py --minimal` / `VFS495_SETUP_MINIMAL=1 driver/tests/hw_test.sh` build the reduced setup.bin.

## T7 run 11: the minimal setup.bin with the driver (2026-10-10)
`driver/tests/hw_test.sh capture 10` with the full setup.bin, then with `VFS495_SETUP_MINIMAL=1` (13 setup
commands, only the 693 + 1301 B init patches), back to back, same finger. Scored together with vfs495-match:

| pairs | mean | >= 40 |
|-------|------|-------|
| full vs full (10 prints)    | 54.6 | 61/90 (68 %) |
| minimal vs minimal (10)     | 60.6 | 64/90 (71 %) |
| full vs minimal             | 56.2 | 118/200 (59 %) |

- **The driver captures with the minimal setup: 10/10 prints, and it scores as well as the full one.** The
  probe's lower M-vs-M (run 10) was swipe variance.
- One bad swipe per set: full 07 matches nothing (mean 12.6, 0/19); without it full vs full is 64.5, 61/72.
  Minimal 09 is weak (28.0, 2/19). They pull the cross score down.
- Lower than phase 6 (71.7), in both sets alike: a different day / swipes, not the setup.

**Result (one sensor): the sensor works with HP's two init patches alone** (693 B bootstrap + 1301 B session).
The 405 B and 2581 B setup patches, HP's 1301 B reload, the 2666 B config and TLV types 23/27 aren't needed for
capture or print quality. setup.bin then holds 2 of the 4 patches (~2 KB of HP code instead of ~5 KB) and 13
instead of 24 setup commands per swipe. Still needs HP's binary once (the two patches are per-sensor too).
Not yet checked: enroll / verify through fprintd over days, suspend/resume, a second sensor.

## WHOLE-BINARY RE with REA/Ghidra (2026-10-23) -> docs/BINARY_RE.md
Full pass over `validity-sensor` with REA (rea-agents 6.7.0) on a Ghidra 12.1.2 backend; every subsystem
mapped and the interop-critical crypto re-derived and byte-verified. Organised reference:
**docs/BINARY_RE.md**. Confirms the earlier findings and fills the gaps.

New / confirmed:
- CLI: 54-command table (`*0x86fbb8`), `main` gate + the 5-byte patch, `gMode` flag bits.
- Transport: EP 0x01/0x81/0x82, frame `[op][payload]` LE, reply `[status:u16 LE]` (`0x04xx` = error class).
  `0x17` is BOTH GetFingerState (pre-session) AND the SSLv3 app-data record byte (content type 23) — same
  byte, demuxed by session state; secure gate `dev+0x76c` lets only `0x04`/`0x17` through plaintext.
  Opcode fixups: peek=`0x07`, poke=`0x08` (0x04=Abort, 0x05=Reset); arm = the final `0x02` config.
- Storage: the key store is an **"EAT" record image** (magic `EAT`+`0x21`/`0x22`), records
  `{u8 type,u32 off,u32 len}`, data-id==type==slot; SSL keys = records 1/10/11/12/13; SHA-1 integrity
  record `0x0e`; mirrored host-side at `SOFTWARE\Validity\vfs301\<serial>`.
- At-rest crypto: embedded **AES-256 "GSK Global"** key in `scsDecryptWithGSKGlobal` (0x512620) unwraps
  Global-sealed blobs offline; factory GSK path is a `return 6` stub. RSA verify keys = `gSSPubKeyList`
  @0x637c80. Host-authority **private** key lives host-side (`HAPrivKey`, `SOFTWARE\Validity\sensor.exe\<serial>`).
- Calibration (`scsFalconCal*`): sweep + knee per analog stage; `-nocal` replays stored values.
- Matcher/template: feature extraction (orientation→FFT→phase→minutiae, 500 dpi, ≤76), minutia stride 0x12;
  template = `'o'` + byte-reversed **TEA(32-round, key "digitalpersona98")** block + FtrCode + len
  (`WriteFeatures`/`ReadFeatures`); match = Hough-vote → LSQ → log-likelihood → FAR (default `0x4000`).
  Enrolled templates: `"VAL-ENRL"` container, payload `[0x02]`+the TEA template. Driver uses NBIS instead.
- Provisioning/OTP: `makeprod` burns the SSK/secure bit into OTP irreversibly; `decomm` is a disabled stub.

HP-FREE VERDICT (confirmed): a factory-provisioned sensor (every HP laptop) runs fully HP-free at runtime
(replay captured patches + read EAT keys + GSK-unwrap + SSLv3 + NBIS); the one-time captured `setup.bin`
is the only HP-origin artifact and can't be synthesized. A blank/decommissioned sensor can't be
re-provisioned without HP (patch-signing key + SE-gated DH auth + one-way OTP). Distribution strategy /
libfprint-upstream survey: driver/README.md.
