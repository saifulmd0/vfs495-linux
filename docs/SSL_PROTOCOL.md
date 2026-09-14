# VFS495 secure session — fully reverse-engineered spec

The capture command (`0x02`) is refused with status `0x0404` unless an SSL session is
active (verified on hardware: `tools/test_nossl.py`). So the session is mandatory.
It is a **proprietary SSLv3** stack with custom cipher-suite IDs. All primitives are
standard (RSA-2048, MD5, SHA-1, AES-CBC), so it is implementable with NSS or `cryptography`.

## Cipher suites (custom IDs, `supportedCiphers` @0x637c50, 3 bytes each: id16, keylen)
- `0x0044` = AES-256-CBC + SHA-1  (chosen)      keylen 32
- `0x0043` = AES-192-CBC + SHA-1                keylen 24
- `0x0042` = AES-128-CBC + SHA-1                keylen 16
- `0x0030/31/32` = same ciphers, pre-shared-AES key-exchange variant (not used here)

## Handshake (records tunneled in cmd `0x11`: `11 <u16 LE total_len> <tls_record...>`)
1. **ClientHello** (scsSSLClientHelloWrite): record `16 03 00 <len>`, body
   `01 <u24 len=0x37> 03 00 <32 client_random> 07 <7-byte session id> 00 06 0044 0043 0042 00`.
   (session id present; compression null.) client_random = 4 rand + 28 rand.
2. **ServerHello** reply on ep `0x81`: `16 03 00 <len> 02 <u24> 03 00 <32 server_random> <sid_len> <sid> 0044 00`.
   Parse server_random (32 B) and confirm suite 0x0044. No Certificate is sent.
3. **Sensor RSA public key** comes from the SENSOR, not the host: scsSSLEstablishSession builds
   key = { size 0x100 (2048b), exp 0x10001, modulus 256B read via scsGetDataFromStorage(id=10) }.
   Dumped modulus: `captures/rsa_modulus.bin` (per-sensor; starts bd2f0c74…, exp 65537).
   TODO for driver: issue the storage-read (scsGetDataFromStorage @0x511c30, storage id 10) instead of
   using the dumped constant.
4. **premaster** = `03 00` + 46 random  (48 B).
5. **ClientKeyExchange** (scsSSLClientKeyExchangeWrite → scsSSLRsaPublicEncrypt): RSA-encrypt the 48-B
   premaster with the sensor key (PKCS#1 v1.5) → 256 B, **byte-reversed** on output. Record
   `16 03 00 01 04` + `10 00 01 00` + 256B.
6. **master secret** (scsSSLMasterSecretGenerate) — SSLv3 KDF, for i in 0..2 (salt "A","BB","CCC"):
   `MD5( premaster + SHA1( salt + premaster + client_random + server_random ) )` → master[i*16:].  (48 B)
   (palCryptoDigestInit type 1=SHA1, 2=MD5.)
7. **key block** (scsSSLKeyBlockGenerate) — same KDF, salt "A","BB","CCC",…, fed
   `salt + master + server_random + client_random`, until 136 B: split as
   client_MAC(20) server_MAC(20) client_key(32) server_key(32) client_IV(16) server_IV(16).
8. **ChangeCipherSpec** `14 03 00 00 01 01`, then **Finished** (scsSSLFinishedWrite/HsHashFinish):
   label 'CLNT' = 0x434c4e54; SSLv3 finished =
   `MD5( master + pad2(0x5c×48) + MD5( handshake_msgs + 'CLNT' + master + pad1(0x36×48) ) )` and the
   SHA1 equiv concatenated (12+ bytes per SSLv3). Sent AES-encrypted.
   Server Finished label 'SRVR' = 0x53525652.

## Record encryption (scsSSLRecordPack, once cipher active — flag 0x13c&2)
- MAC (scsSSLMacSha, SSLv3): `SHA1( mac_key[20] + pad2(0x5c×40) + SHA1( mac_key[20] + pad1(0x36×40)
  + seq[8] + type[1] + len[2] + data ) )`. seq starts 0, increments per record.
- pad payload to 16-B AES block (SSLv3 padding, last byte = padlen-1), AES-256-CBC encrypt with
  client_key/client_IV (CBC chains the last ciphertext block as next IV).
- AppData records after the handshake are sent as raw bulk writes `17 03 00 <len> <ciphertext>`
  (NOT tunneled in 0x11); replies likewise on ep 0x81. Decrypt with server_key/server_IV/server_MAC.

## Wrapped payload
Once the session is up, the VCSFW capture command `0x02` (+ its config blob; captured plaintext in
`captures/plaintext_cmds_full.txt`) is sent as AppData; the image still returns PLAINTEXT on ep 0x82.

## Implementation status (tools/ssl_session.py) — crypto ALL validated byte-exact vs hardware
VALIDATED against gdb dumps of the real driver (each MATCHES exactly):
- master secret + key block KDF (kdf_vector.json): SSLv3 MD5/SHA1 PRF; master=PRF(pre,cR,sR),
  keyblock=PRF(master,sR,cR). keyblock 136B = cMAC20 sMAC20 cKey32 sKey32 cIV16 sIV16.
- Finished (finished_vec.json): SSLv3, label hashed as LE int 0x434c4e54 (bytes 54 4e 4c 43), NOT ascii.
- Record encryption (rec_vec.json): AES-256-CBC + SSLv3 MAC. **MAC omits the length** (only seq+type+data)
  — Validity variant. CBC IV chains from prev ciphertext.
- RSA (rsa_em*.json, wire_order.json): **modulus is stored LITTLE-ENDIAN** (as big-endian it's 2047-bit
  even = invalid); exp 65537 (bytes 01 00 01 00 read as native LE int); PKCS#1 v1.5, premaster at EM
  offset 208; wire = big-endian C (palCrypto + scsSSL each byte-reverse -> cancels). pow(EM_be,e,n_le)==C
  and wire==C_be both verified.

OPEN (blocks completion): the assembled handshake is rejected by the SENSOR with a fatal SSL alert
`15 03 00 00 02 02 2f` (level 2, desc 0x2f=47), right after the ClientKeyExchange flight. Every primitive
above is byte-exact, framing matches the capture (ClientHello tunnel 11 3c 00…, flight tunnel 11 54 01 =
CKE 265 + CCS 6 + Finished 69), ServerHello parses, no extra server data. 0x2f is generated by the sensor
firmware (not in the host binary), so its exact trigger isn't in the decompile. Hypotheses to try next:
(a) sensor SSL state not fully reset between attempts (tool interleaves 1a UnloadPatch / 06 re-patch —
    replicate the exact capture ordering incl. the post-ServerHello patches);
(b) premaster version-byte / client_version check nuance;
(c) capture MY session over usbmon and diff structurally vs the tool's BEST-swipe capture.

## Reference vectors (one real session, gdb) — `captures/ssl_secrets.json`
premaster / master / keyblock captured for offline KDF validation. (randoms live in a sub-struct;
capture them by breaking in scsSSLClientHelloWrite / scsSSLServerHelloProcess when validating.)
