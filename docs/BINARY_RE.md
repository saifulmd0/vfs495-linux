# VFS495 `validity-sensor` binary — full reverse-engineering reference

Whole-binary RE of HP's `usr/sbin/validity-sensor` (Validity 4.5-136, SoftPaq sp84530), x86-64 ELF,
not stripped (full symbols + DWARF), done with REA (rea-agents 6.7.0) driving a Ghidra 12.1.2 backend
(2026-10-23). sha256 `089322826391fad7735407c28c986cf016ce5817637589235273ab7bde20d353`, image base
`0x400000`, 3159 procedures, 8619 strings. Complements the chronological notes in
[`FINDINGS.md`](FINDINGS.md) and the session spec in [`SSL_PROTOCOL.md`](SSL_PROTOCOL.md); this file is
the organised address-level reference. The MCU is a **Tensilica Xtensa** core; all host crypto is
statically linked (libtommath `mp_*` + an AES/SHA/MD5/RSA PAL), so the OpenSSL `.so.0.9.8` deps are
satisfied by empty stubs.

## Subsystem map (by symbol prefix)
- `scsSSL*` (0x512b80–0x516480) — custom SSLv3 client (spec: `SSL_PROTOCOL.md`).
- `scsFalcon*`, `scsSensorFalcon*` — sensor ASIC calibration + firmware patch/config selection.
- `irDliRT*`, `UnpackLineRT`, `computeNCCForZeroLagInverted` — descramble + swipe assembly.
- `scsSensor*` — ownership, certificate, flash storage, abort.
- `xvfs*`, `fss*` — on-sensor flash filesystem / EAT partitions.
- `pal*` — platform: USB, crypto (RSA/ECC/AES/DH), timers, tag-value store, PnP.
- `DigitalPersona::FpRecEngineImpl` — feature extraction + minutiae matcher + template (STLport C++).
- `vcs*` — top-level API; `vcsTest*` — diagnostic commands; `vcsDatabase*` — template DB (dss).
- `ids*` — WIT/identity subsystem.

## Entry & CLI dispatch
`_start` → `__libc_start_main` → `main` (0x4411e0). Shipped `main` is a **gate**: only `setowner -doinit`
/ `resetowner -doinit` reach `Execute`; the 5-byte patch at va `0x44122d` (`48 8b 7b 08` → `e9 82 00 00
00`, jmp 0x4412b4) bypasses it (see `runtime/README.md`). `Execute` (0x4403b0) parses global flags, then
`FindFunction(argv[1])` → a 54-entry `{name, handler}` table (`*0x86fbb8` → 0x8705e0, stride 0x10), opens
the sensor with `GetSensor(gMode)`, and calls the handler.

Global flags → `gMode` bits: `-nossl` `0x100`, `-nocal` `0x4000000`, `-lock` clears `0x100000`, `-doinit`
clears `0x80000000`; also `-sec`, `-internalcfg` (needs `-doinit`), `-swipespeed`/`-soclock`/`-flexid N`.

### Command table (54 entries)
`ver`/`getver`, `res`/`reset`, `peek`, `poke`, `getpr`/`getprint`, `getprintwait`, `stop`/`stopprint`,
`unl`/`unloadpatch`, `patch`, `script`, `send`, `gpio`, `getf`/`getfstate`, `bulk`, `spi`/`spitrans`,
`spibulkread`, `spiflashwrite`, `setclk`, `readram`, `setrefclk`, `woeenter`, `woesetup`, `getstartinfo`,
`getconfig`, `setspimode`, `cal`/`calibrate`, `flashinfo`, `provision`, `setowner`/`setowner_sim`/
`setowner_with_keys`, `resetowner`, `decomm`, `lock`, `sensorstat`, `sslstat`, `getsignature`, `read_otp`,
`set_prod_opts`, `get_ownership_info`, `serialize`, `get_cert`, `get_auth_data`, `getuid`, `genvck`,
`makeprod`.

## USB transport & command framing
libusb-0.1, bulk only; VID `0x138a` is the only match filter. Endpoints: **OUT 0x01** commands,
**IN 0x81** replies, **IN 0x82** image stream (read in 0x4000-byte chunks). Workers drain descriptor
queues (`usbSensorRequestDpc` 0x522440, `usbSensorFpDataDpc` 0x522260); requests matched to replies by a
32-bit sequence tag. Transport block size 0x40 (0x20 on `[dev+0x1d4]` ∈ {2,3}).

Command = `[opcode:1][payload]`, little-endian throughout (`palSensorToHost16/32` are identity). Reply =
`[status:u16 LE][payload]`, `0x0000` = OK; failures are the `0x04xx` class (trace tokens `2b04`/`5004`/
`0404`/`6d04` = `0x042b`/`0x0450`/`0x0404`/`0x046d`). Zero-length reply = sensor reset → re-enumerate.
`scsSend` wraps commands as SSLv3 records once a session is up (`scsSSLEncrypt` → `scsSSLAppDataWrite` →
`scsSSLRecordPack(…, 0x17, …)`, i.e. content type 23). The secure gate `dev+0x76c` then allows only
`0x04` (abort) and `0x17` through in clear.

### Command opcodes (first payload byte)
`0x01` GetVersion, `0x02` config/arm (LE u16 size at off 1, cached `dev+0x768`), `0x04` Abort,
`0x05` Reset, `0x06` DownloadPatch, `0x07` Peek `(addr:u32, width:u8)`, `0x08` Poke, `0x0d` GPIO
(9 banks × {value:u32, mask:u32}), `0x11` SSL handshake tunnel, `0x17` GetFingerState **and** SSL
application_data, `0x19` GetStartInfo, `0x1a` UnloadPatch (reply = BE u16 status), `0x1f` SPI bulk read,
`0x22` GetCertificate, `0x28` DH session key, `0x2f` GenVCK. Register space is flat 32-bit: timeslot/
capture regs `0x30042800…0x30042d7c`, CPU RAM at `0x60000000`. SPI flash is tunnelled via SPITrans
(JEDEC `03` read, `02` page-program, `06` WREN, `c7` erase, `05` RDSR).

`getfstate` (0x17, `SensorGetFingerStatus` 0x43b700): reply `status:u16, state:u8` (0 UNKNOWN / 1 ABSENT
/ 2 STILL / 3 MOVING), `accumwoe:u32` (FINGER 0x10, TIMER 0x8, RESET 0x4, GPIO 0x20, SPI 0x40, USB 0x80,
PP 0x100, ABORT 0x200).

## Device init & lifecycle
`GetSensor` (0x4417a0) → `vcsTestInitializeEx(&h, gMode, params, vcsClientEventsCallback, &ctx)`. Param
tags: **4 = SignDataByHAPrivKey**, **5 = GetSensorPubKey** (both always registered), 1/2/3 =
swipe/soclock/flexid. `scsSubsystemStartup` (0x4f8d00) brings up PAL → PnP → USB and builds four
sensor-type records linking the built-in config lists by kind: **0 patch, 1 print, 2 cal, 3 (unnamed),
4 WOE** (`falcon*ConfigList`, the `-internalcfg` source). Per-device bring-up (`scsSensorDeviceStartup`
0x4f7400) clears `dev+0x76c`, then **GetStartInfo (0x19)** fills the sensor-info record
(`type@+8, ver@+9, id@+4, flexid@+0x1a`) that every patch/config selector keys on.

Bring-up order: USB open → GetStartInfo → load 4 patches (`0x06`; bootstrap→session→setup→calibration) →
push configs (`0x02`) → calibrate (unless `-nocal`) → SSLv3 session (unless `-nossl`; state stays `0x174`
= "security API only") → arm → stream. Event model (`vcsClientEventsCBEx` 0x4432a0): 64-bit subscription
mask, event `{id:u32, status:u32, dataSize:u32, data@+0x10}`; ids 3 = sensor-ready, 8 = waiting-for-finger,
6 = swipe-complete, 0xd1 = reply-ready.

## Firmware patches & config
`SensorDoPatch` (0x43eb80, `patch`) frames `0x06 ‖ body` from an Intel-HEX file; the body carries the
per-sensor authentication and is sent verbatim (host never signs). `SensorUnloadPatch` (0x437cb0) sends
`0x1a`. Patch/config **selection** is host-side table logic (`scsFalconFindPatchEx` 0x510f40, stride 0x48;
`scsFalconFindPrintConfig` 0x5115c0; `scsFalconFindWoeConfig` 0x5112b0) matched on the sensor-info record
+ capability/kind flags.

Config reply (`scsFalconParseConfigReply` 0x511380) = `{u32 len, u32 pad, void* data}`;
`scsFalconFindTsTblInConfigReply` (0x511360) sets the **timeslot table = the first 0x580 (1408) bytes** of
the config data (this is the descramble table UnpackLineRT reads). Config body is little-endian TLV
(`u16 type, u16 len, value`): **type 5** = pixel depth/packing, **type 6** = the stream key block,
types 7/19/20/23/27/29 = TLVs a bare ROM lacks. `scsFalconConvertPrintConfig` (0x511410) recomputes the
line stride `(((bytesPerLine-8)*bits + 7) >> 3) + 0x17 & 0x3ffffff0`.

The shipped per-model firmware is `usr/sbin/HPUsbVFS495.img` (315392 B): header `_VEH` ‖
`HPUsbVFS495.VALIDITY\0` ‖ type/version `0b 05 04`, then a fully-encrypted body (entropy 7.99).

## Falcon calibration
`scsSensorFalconCalibrate` (0x4fcb20) is a step machine: load the cal patch → for each analog stage
{CommDet, PGA offset, ADC, PGA gain, ASP LNA, ASP PGA, (WOE)} push a stage config, capture counted lines,
**sweep a register bitfield and pick the response knee** (`scsFalconCalNextSweepValue` 0x50bf20,
`scsFalconCalChooseValuesWithRCAlg` 0x50b660), bounds-check vs per-sensor limits → write chosen values to
dev regs 0x410/0x480/0x48c/0x490 → restore run patch → persist. Output persists to
`/etc/ValidityPersistentData` (`SOFTWARE\Validity\vfs301\<serial>`) and rides in the config/timeslot
blobs. `-nocal` (gMode `0x4000000`) or `calibrationEnable=0` replays stored values. An interop driver
does not reimplement this — the tuned register values are per-device data captured in `setup.bin`.

## WOE (wait-on-finger / low-power)
Optional standby where the sensor watches for a finger. Support = `*(dev+0x650) != 0` (`scsIsWoeSupported`
0x4e7140). `woesetup` (0x43b660) builds the WOE blob from calibration + flexid
(`scsFalconCalGetWoeSetup` 0x50b8c0, thresholds from cal stage `scsFalconCalWoe` 0x510610) and sends it;
`woeenter` (0x43d2c0) → `vcsTestWOEEnter(timeout:u16=10s)`. Wake is reported via the `get_finger_status`
(0x17) `accumwoe` bits (FINGER 0x10 vs TIMER 0x8). A driver may skip WOE and just arm + poll.

## Capture + image pipeline
`getprint`/`SensorGetPrint` (0x43f9f0) → `vcsTestGetRawScanlines`. Arming is the final `0x02` config (it
carries the per-swipe AES key in its type-6 TLV; `scsStartReadFingerprint` 0x4ec1a0). The stream parser
`irDliRTFalconData` (0x462350) frames each scanline on `01 {01|FE}` (fixed length `ctx[0x170]`, 8-byte
header), then:
- **Descramble** `UnpackLineRT` (0x46f510): config `cfg[0]` = mode, `cfg[1]` = columns, byte array
  `cfg+8` = per-column bit widths, **`int16[]` permutation at `cfg+0x57c`** = destination column per
  sample. Modes: 4 (byte → two nibbles), 8 (straight copy through the permutation), else variable-bit
  MSB-first. The permutation is the per-device descramble key (from the timeslot table).
- **Assemble** `vcsDoIR` → `computeNCCForZeroLagInverted` (0x470c80): motion-compensate successive rows by
  normalized cross-correlation with inverted pixels (64-byte windows), best vertical lag = finger advance;
  `IRhandleInvertAndFlip` (0x465900) does the final invert + vertical flip.
- End-of-swipe: per-line variance `getQuasiLineVariance` below ~13 sustained → stream trailer
  `01 01 00 NN …`, then `0x04` abort.
Geometry: 264 columns (0–199 main image, 200–263 aux/tracking row), ~500 dpi, dynamic height. The stream
is decrypted upstream with the per-swipe AES-256-CBC key installed at arming.

## Secure session & key storage
Full spec in [`SSL_PROTOCOL.md`](SSL_PROTOCOL.md): proprietary SSLv3 (version `03 00`), AES-CBC + SSLv3
SHA-1 MAC (not HMAC), MD5∘SHA1 PRF, RSA key-exchange ciphertext byte-reversed on the wire, CBC IV chained
across records. Handshake tunnelled in cmd `0x11`; application data as raw `17 03 00 <len>` records.

`scsSSLEstablishSession` (0x515870) pulls key material with `scsGetDataFromStorage` (0x511c30) from the
sensor's EAT flash:

| id | len | meaning |
|----|-----|---------|
| 1 | 0x20 | 32-byte pre-shared secret (cleartext cache `dev+0x560`) |
| 10 | 0x100 | server RSA-2048 modulus (key-exchange key) |
| 11 | 0x100 | signature certifying id 10 |
| 12 | 0x100 | host RSA public key |
| 13 | 0x4a0 | host RSA private-key blob (key 0x494) |

`scsSensorValidateCertificate` (0x4e8dd0) verifies each on-sensor key (SHA-256 + RSA-2048, e=0x10001)
against a firmware root key table `gSSPubKeyList` @ `0x637c80` (stride 0x103 records
`{type, version, windsorFlag, RSA-2048 modulus}`; first = type 04, ver 0x28). Non-"Windsor" moduli and
signatures are byte-reversed.

### Flash storage layout (EAT)
The raw partition (`xvfs*`/`fss*`) is an **"EAT" record image** (`gEATSignature` @0x555880; version byte
`0x21` = 64 KiB, `0x22` = 4 KiB Windsor), records `{u8 type, u32 offset, u32 length}`; data ID = record
type = slot (`scsGetDataSlotFromDataID` 0x5118e0). Integrity = SHA-1(20) stored as record `0x0e`
(`CalculateRAWPartitionHash` 0x4e3880; skipped when `scsSensorIsAESSecured`). The whole image is mirrored
host-side and reloaded (`scsDeSerializeRawPartition` 0x4ea810) from
`SOFTWARE\Validity\vfs301\<6-byte-serial>` (`/etc/ValidityPersistentData`); `xvfsStorageOpen(dev, 1)` =
raw partition.

### At-rest encryption
`scsGetSSProtector` (0x511990): mode 0 cleartext, mode 1 **GSK Global**, mode 2/3 GSK factory (stub,
`return 6` — not in the host binary). `scsDecryptWithGSKGlobal` (0x512620) holds a **hardcoded AES-256
key** (built via immediate stores): `71 7c d7 2d 09 62 bc 4a 28 46 13 8d bb 2c 24 19 25 12 a7 64 07 06 5f
38 38 46 13 9d 4b ec 20 33`; AES-256-CBC, applied when the blob version byte ≥ 2; blob =
`[ver][flag][crc32][IV:16][ciphertext]` (offsets −4 when version 0). The root of this key is the **SSK**
burned into OTP fuses at `makeprod`.

## Ownership, provisioning & OTP (the HP-only part)
State machine: unowned → owned (password, op `0x1c`; `0x1d` with keys) → [locked] → re-ownable with a
finite cycle budget (`get_ownership_info` returns total + available). `decomm` is a disabled stub.
`provision`/`makeprod`/`serialize`/`set_prod_opts` burn OTP fuses (SSK, VCK_IV, secure bit, serial;
write-once, 0→1 only); `makeprod` is irreversible. `get_cert` = op `0x22`; `genvck` = op `0x2f`;
`get_auth_data` (0x438cb0) reads `./auth_data.bin` (HP challenge) → the sensor SE computes `auth_token.bin`
over a 128-bit DH (`scsDHEstablishSessionKey` 0x516700, op `0x28`, embedded modulus/salt, behind an
HP-signed auth patch). The host-authority RSA **private** key is stored host-side as value `HAPrivKey`
(+ `SPrivMod`) under `SOFTWARE\Validity\sensor.exe\<serial>` and used by the `SignDataByHAPrivKey`
callback; on a provisioned machine it already exists.

## DigitalPersona matcher & template (host-side, no sensor)
Feature extraction `FeatureExtractionBase::ExtractMinutia` (0x4b0260): orientation map
(`orientation_map_and_footprint<256,4>` 0x4ae550) → FFT contextual enhance (0x4a9c00) → ridge phase
(`freeman_phasemap` 0x4aa5c0) → minutiae (`extract_minutia` 0x4ab380) → weight/cap at 76
(`MinutiaPoints<76>::ComputeWeights`). Minutia struct stride **0x12 (18 B)**: `+0 X:u16, +2 Y:u16,
+0xe angle:u16, +0xc/+0xf attributes`; count at MatchData+0x558. Nominal 500 dpi.

Template serialization (`WriteFeatures` 0x4b94c0 / `ReadFeatures` 0x4c0d90): record =
`'o'(0x6f) ‖ byte-reversed, TEA-stream-ciphered minutiae block ‖ FtrCode(2) ‖ length(2)`. Cipher is
**classic TEA, 32 rounds**, delta `0x9E3779B9`, sum terminates `0xC6EF3720`; **default 16-byte key =
ASCII `"digitalpersona98"`** (immediates `0x706c617469676964` / `0x3839616e6f737265`). Key words are
whitened `k ^ {0x23650935, 0x79642590, 0x51806878, 0x91341639}`; block state seeded
`v0=0x35096523, v1=0x78688051`. `MatchDataSerializer::Write` (0x4b8470) emits reverse-TLV sections
(payload ‖ u16 len ‖ u8 tag; tags 3/4/6/0x0a/0x0b) and the minutiae stream (Y-sorted, ΔY 1–2 B, X 1–2 B,
angle, quality). `DecompressFeatures` (0x483ba0) is a separate parser for the sensor's on-wire minutiae
packet (u24 origin + packed 11-bit X / 11-bit Y / 8-bit angle).

Matcher `VFIdentifyStart` (0x4843c0): Hough vote over minutia pairs → rigid alignment
(`ContinousVoting::alignment` = 8-bit rotation + packed translation) → tolerance-gated pairing + heap
selection → least-squares refine → **log-likelihood score** (`CorrFinder::get_score_using_all` 0x4a1040;
tables `pow10_x_10`, `log2_256_8::LogTable`, `log_factorial_table`). `DPFRGetVerificationResult` (0x4bd4e0)
accepts iff `requestedFAR ≤ pow10_x_10[score]` (default FAR `0x4000`). Enrolled templates are stored in
the `vcsDatabase*` store as a **`"VAL-ENRL"`** container (`+9 u32 tplLen, +0xd u32 auxLen, +0x11 template,
tail 32-byte PEK`) whose template payload is `[0x02] ‖` the `'o'`+TEA template. The native driver uses
libfprint/NBIS instead; this is only needed to read HP-enrolled templates.

## What an HP-free driver needs
On a **factory-provisioned** sensor (every HP laptop): replay the captured signed patches (`0x06`), read
the EAT key store (ids 1/10/11/12/13, GSK-unwrap with the embedded AES-256 key), run the SSLv3 handshake,
arm, stream, assemble, match with NBIS — **no HP binary, daemon, or network at runtime**. The one
HP-origin artifact is the signed patch/config blobs captured once into `setup.bin` (see
`runtime/README.md`), which cannot be synthesized (sensor-ROM-verified) and must not be redistributed. A
**blank / decommissioned** sensor cannot be re-provisioned without HP: patch signing needs HP's RSA
private key, ownership needs the SE-gated DH auth, and the OTP SSK/secure bit are burned irreversibly —
hard walls independent of this driver. Distribution strategy and the libfprint-upstream survey:
[`../driver/README.md`](../driver/README.md#distribution--upstreaming).
