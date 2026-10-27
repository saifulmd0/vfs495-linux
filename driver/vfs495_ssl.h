/*
 * Validity VFS495: the sensor's SSLv3 session, protocol layer (no USB). docs/SSL_PROTOCOL.md;
 * port of tools/ssl_session.py. Validity quirks:
 *  - ClientKeyExchange: PKCS#1 v1.5 with the modulus stored little-endian, message + output big-endian
 *  - Finished labels CLNT/SRVR hashed as little-endian integers; the sensor's Finished covers the same
 *    handshake messages as ours (our Finished is not hashed in)
 *  - record MACs leave out the length field
 * All randomness is passed in, so tests can replay fixed vectors (tests/test_ssl.sh).
 */
#pragma once

#include <glib.h>

#define VFS495_SSL_RANDOM_LEN    32
#define VFS495_SSL_PREMASTER_LEN 48
#define VFS495_RSA_LEN           256

#define VFS495_REC_CCS       0x14
#define VFS495_REC_ALERT     0x15
#define VFS495_REC_HANDSHAKE 0x16
#define VFS495_REC_APPDATA   0x17

typedef struct
{
  guint8  mac[20];
  guint8  key[32];
  guint8  iv[16];                    /* CBC chains across records (SSLv3) */
  guint64 seq;
} Vfs495SslDir;

typedef struct
{
  Vfs495SslDir tx, rx;               /* host -> sensor, sensor -> host */
} Vfs495Ssl;

typedef struct
{
  guint8      client_random[VFS495_SSL_RANDOM_LEN];
  guint8      premaster[VFS495_SSL_PREMASTER_LEN];
  guint8      master[48];
  GByteArray *msgs;                  /* handshake messages hashed into Finished */
} Vfs495Handshake;

/* Storage entry `id` of the 4 KiB flash block init reads (id 10 = the RSA session key). */
GBytes     *vfs495_flash_storage (const guint8 *flash,
                                  gsize         len,
                                  guint8        id);

/* Wrap an SSL record for the command endpoint: 11 <u16 LE len> record. */
GByteArray *vfs495_tunnel (const guint8 *record,
                           gsize         len);

void        vfs495_handshake_init (Vfs495Handshake *hs,
                                   const guint8     client_random[VFS495_SSL_RANDOM_LEN],
                                   const guint8     premaster[VFS495_SSL_PREMASTER_LEN]);
void        vfs495_handshake_clear (Vfs495Handshake *hs);

/* Tunnelled ClientHello. */
GByteArray *vfs495_handshake_hello (Vfs495Handshake *hs);

/* From the sensor's ServerHello reply: derive the keys into `ssl` and return the tunnelled second
 * flight (ClientKeyExchange, ChangeCipherSpec, encrypted Finished). `pad` = the non-zero PKCS#1
 * padding bytes (VFS495_RSA_LEN - 3 - VFS495_SSL_PREMASTER_LEN of them). */
GByteArray *vfs495_handshake_flight (Vfs495Handshake *hs,
                                     Vfs495Ssl       *ssl,
                                     const guint8    *server_hello,
                                     gsize            len,
                                     const guint8    *modulus_le,
                                     gsize            modulus_len,
                                     const guint8    *pad,
                                     GError         **error);

/* Check the sensor's reply to the second flight (CCS + encrypted Finished). */
gboolean    vfs495_handshake_verify (Vfs495Handshake *hs,
                                     Vfs495Ssl       *ssl,
                                     const guint8    *reply,
                                     gsize            len,
                                     GError         **error);

/* One encrypted record (header included). */
GByteArray *vfs495_ssl_encrypt (Vfs495Ssl    *ssl,
                                guint8        type,
                                const guint8 *data,
                                gsize         len);

/* Decrypt and MAC-check every record in a sensor reply; returns the concatenated payloads.
 * A plaintext alert (the sensor dropped the session) is an error. */
GByteArray *vfs495_ssl_decrypt (Vfs495Ssl    *ssl,
                                const guint8 *reply,
                                gsize         len,
                                guint8       *last_type,
                                GError      **error);
