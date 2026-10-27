/*
 * Validity VFS495: the sensor's SSLv3 session, protocol layer. See vfs495_ssl.h.
 *
 * This library is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License, version 2.1 or later.
 */

#include <string.h>

#include <gio/gio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

#include "vfs495_ssl.h"

#define HS_FINISHED_LEN 36             /* MD5 + SHA-1 */

static const guint8 label_clnt[4] = { 0x54, 0x4e, 0x4c, 0x43 };   /* 0x434C4E54 little endian */
static const guint8 label_srvr[4] = { 0x52, 0x56, 0x52, 0x53 };   /* 0x53525652 little endian */

/* ---- hashing ------------------------------------------------------------ */

typedef struct
{
  const guint8 *p;
  gsize         n;
} Part;

static void
digest (const EVP_MD *md, const Part *parts, guint nparts, guint8 *out)
{
  EVP_MD_CTX *ctx = EVP_MD_CTX_new ();

  EVP_DigestInit_ex (ctx, md, NULL);
  for (guint i = 0; i < nparts; i++)
    EVP_DigestUpdate (ctx, parts[i].p, parts[i].n);
  EVP_DigestFinal_ex (ctx, out, NULL);
  EVP_MD_CTX_free (ctx);
}

/* SSLv3 key derivation: MD5(secret + SHA1('A' x i+1 + secret + a + b)) blocks. */
static void
ssl3_prf (const guint8 *secret, gsize slen,
          const guint8 *a, const guint8 *b,
          guint8 *out, gsize n)
{
  for (guint i = 0; n > 0; i++)
    {
      guint8 salt[16], sha[20], md5[16];
      gsize k = MIN (n, 16);

      memset (salt, 'A' + i, i + 1);
      digest (EVP_sha1 (), (Part[]) { { salt, i + 1 }, { secret, slen },
                                      { a, VFS495_SSL_RANDOM_LEN }, { b, VFS495_SSL_RANDOM_LEN } }, 4, sha);
      digest (EVP_md5 (), (Part[]) { { secret, slen }, { sha, 20 } }, 2, md5);
      memcpy (out, md5, k);
      out += k;
      n -= k;
    }
}

static void
ssl3_finished (const guint8 master[48], const GByteArray *msgs, const guint8 label[4],
               guint8 out[HS_FINISHED_LEN])
{
  guint8 pad1[48], pad2[48], inner[20];

  memset (pad1, 0x36, sizeof (pad1));
  memset (pad2, 0x5c, sizeof (pad2));
  digest (EVP_md5 (), (Part[]) { { msgs->data, msgs->len }, { label, 4 }, { master, 48 }, { pad1, 48 } }, 4, inner);
  digest (EVP_md5 (), (Part[]) { { master, 48 }, { pad2, 48 }, { inner, 16 } }, 3, out);
  digest (EVP_sha1 (), (Part[]) { { msgs->data, msgs->len }, { label, 4 }, { master, 48 }, { pad1, 40 } }, 4, inner);
  digest (EVP_sha1 (), (Part[]) { { master, 48 }, { pad2, 40 }, { inner, 20 } }, 3, out + 16);
}

/* Validity's SSLv3 MAC: seq + type + data, no length field. */
static void
record_mac (const Vfs495SslDir *d, guint8 type, const guint8 *data, gsize len, guint8 out[20])
{
  guint8 pad1[40], pad2[40], hdr[9], inner[20];

  memset (pad1, 0x36, sizeof (pad1));
  memset (pad2, 0x5c, sizeof (pad2));
  for (guint i = 0; i < 8; i++)
    hdr[i] = d->seq >> (56 - 8 * i);
  hdr[8] = type;
  digest (EVP_sha1 (), (Part[]) { { d->mac, 20 }, { pad1, 40 }, { hdr, 9 }, { data, len } }, 4, inner);
  digest (EVP_sha1 (), (Part[]) { { d->mac, 20 }, { pad2, 40 }, { inner, 20 } }, 3, out);
}

static gboolean
aes_cbc (gboolean enc, const guint8 key[32], const guint8 iv[16],
         const guint8 *in, gsize len, guint8 *out)
{
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new ();
  int n1 = 0, n2 = 0;
  gboolean ok;

  ok = EVP_CipherInit_ex (ctx, EVP_aes_256_cbc (), NULL, key, iv, enc) &&
       EVP_CIPHER_CTX_set_padding (ctx, 0) &&
       EVP_CipherUpdate (ctx, out, &n1, in, len) &&
       EVP_CipherFinal_ex (ctx, out + n1, &n2) &&
       (gsize) (n1 + n2) == len;
  EVP_CIPHER_CTX_free (ctx);
  return ok;
}

/* PKCS#1 v1.5 type 2 with the Validity byte order. */
static gboolean
rsa_encrypt (const guint8 *modulus_le, gsize mlen, const guint8 *msg, gsize msglen,
             const guint8 *pad, guint8 out[VFS495_RSA_LEN])
{
  guint8 em[VFS495_RSA_LEN], mod_be[VFS495_RSA_LEN];
  gsize padlen = VFS495_RSA_LEN - 3 - msglen;
  BN_CTX *ctx = BN_CTX_new ();
  BIGNUM *n = BN_new (), *m = BN_new (), *e = BN_new (), *c = BN_new ();
  gboolean ok;

  if (mlen != VFS495_RSA_LEN)
    return FALSE;
  for (gsize i = 0; i < mlen; i++)
    mod_be[i] = modulus_le[mlen - 1 - i];
  em[0] = 0x00;
  em[1] = 0x02;
  memcpy (em + 2, pad, padlen);
  em[2 + padlen] = 0x00;
  memcpy (em + 3 + padlen, msg, msglen);

  ok = BN_bin2bn (mod_be, mlen, n) && BN_bin2bn (em, sizeof (em), m) && BN_set_word (e, 0x10001) &&
       BN_mod_exp (c, m, e, n, ctx) && BN_bn2binpad (c, out, VFS495_RSA_LEN) == VFS495_RSA_LEN;
  BN_free (n);
  BN_free (m);
  BN_free (e);
  BN_free (c);
  BN_CTX_free (ctx);
  return ok;
}

/* ---- records ------------------------------------------------------------ */

static void
put_record_header (GByteArray *out, guint8 type, gsize len)
{
  guint8 hdr[5] = { type, 3, 0, len >> 8, len & 0xff };

  g_byte_array_append (out, hdr, 5);
}

GByteArray *
vfs495_ssl_encrypt (Vfs495Ssl *ssl, guint8 type, const guint8 *data, gsize len)
{
  gsize body = len + 20, padlen = 16 - body % 16, ctlen = body + padlen;
  g_autofree guint8 *plain = g_malloc (ctlen);
  GByteArray *out = g_byte_array_sized_new (5 + ctlen);

  memcpy (plain, data, len);
  record_mac (&ssl->tx, type, data, len, plain + len);
  ssl->tx.seq++;
  memset (plain + body, padlen - 1, padlen);

  put_record_header (out, type, ctlen);
  g_byte_array_set_size (out, 5 + ctlen);
  aes_cbc (TRUE, ssl->tx.key, ssl->tx.iv, plain, ctlen, out->data + 5);
  memcpy (ssl->tx.iv, out->data + 5 + ctlen - 16, 16);
  return out;
}

static gboolean
decrypt_one (Vfs495Ssl *ssl, guint8 type, const guint8 *ct, gsize len, GByteArray *out, GError **error)
{
  g_autofree guint8 *plain = NULL;
  guint8 mac[20];
  gsize n;

  if (len == 0 || len % 16)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "sensor record of %zu B is not encrypted", len);
      return FALSE;
    }
  plain = g_malloc (len);
  aes_cbc (FALSE, ssl->rx.key, ssl->rx.iv, ct, len, plain);
  memcpy (ssl->rx.iv, ct + len - 16, 16);
  if ((gsize) plain[len - 1] + 1 + 20 > len)
    goto bad;
  n = len - plain[len - 1] - 1 - 20;
  record_mac (&ssl->rx, type, plain, n, mac);
  ssl->rx.seq++;
  if (memcmp (mac, plain + n, 20) != 0)
    goto bad;
  g_byte_array_append (out, plain, n);
  return TRUE;

bad:
  g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "bad MAC on sensor record type %#x", type);
  return FALSE;
}

GByteArray *
vfs495_ssl_decrypt (Vfs495Ssl *ssl, const guint8 *reply, gsize len, guint8 *last_type, GError **error)
{
  g_autoptr(GByteArray) out = g_byte_array_new ();
  gsize p = 0;

  while (p + 5 <= len)
    {
      guint8 type = reply[p];
      gsize n = (reply[p + 3] << 8) | reply[p + 4];

      if (p + 5 + n > len)
        break;
      if (type == VFS495_REC_ALERT && n % 16)
        {
          g_set_error (error, G_IO_ERROR, G_IO_ERROR_CONNECTION_CLOSED,
                       "sensor dropped the session (alert %02x)", n ? reply[p + 5 + n - 1] : 0);
          return NULL;
        }
      if (!decrypt_one (ssl, type, reply + p + 5, n, out, error))
        return NULL;
      if (last_type)
        *last_type = type;
      p += 5 + n;
    }
  return g_steal_pointer (&out);
}

/* ---- handshake ---------------------------------------------------------- */

GBytes *
vfs495_flash_storage (const guint8 *flash, gsize len, guint8 id)
{
  const gsize base = 0x1000;

  for (gsize p = 13; p + 10 <= len && flash[p] == 0xff; p += 10)
    {
      guint32 addr = flash[p + 2] | (flash[p + 3] << 8) | (flash[p + 4] << 16) | ((guint32) flash[p + 5] << 24);
      guint32 size = flash[p + 6] | (flash[p + 7] << 8) | (flash[p + 8] << 16) | ((guint32) flash[p + 9] << 24);

      if (flash[p + 1] == id && addr >= base && (gsize) (addr - base) + size <= len)
        return g_bytes_new (flash + addr - base, size);
    }
  return NULL;
}

GByteArray *
vfs495_tunnel (const guint8 *record, gsize len)
{
  GByteArray *out = g_byte_array_sized_new (3 + len);
  guint8 hdr[3] = { 0x11, len & 0xff, len >> 8 };

  g_byte_array_append (out, hdr, 3);
  g_byte_array_append (out, record, len);
  return out;
}

void
vfs495_handshake_init (Vfs495Handshake *hs,
                       const guint8 client_random[VFS495_SSL_RANDOM_LEN],
                       const guint8 premaster[VFS495_SSL_PREMASTER_LEN])
{
  memset (hs, 0, sizeof (*hs));
  memcpy (hs->client_random, client_random, VFS495_SSL_RANDOM_LEN);
  memcpy (hs->premaster, premaster, VFS495_SSL_PREMASTER_LEN);
  hs->premaster[0] = 3;                /* client version SSL 3.0 */
  hs->premaster[1] = 0;
  hs->msgs = g_byte_array_new ();
}

void
vfs495_handshake_clear (Vfs495Handshake *hs)
{
  g_clear_pointer (&hs->msgs, g_byte_array_unref);
  memset (hs, 0, sizeof (*hs));
}

GByteArray *
vfs495_handshake_hello (Vfs495Handshake *hs)
{
  /* SSL 3.0, 7-byte zero session id, suites 0x0044/43/42 (AES-256/192/128-CBC-SHA), no compression */
  static const guint8 head[] = { 0x01, 0x00, 0x00, 0x33, 0x03, 0x00 };
  static const guint8 tail[] = { 0x07, 0, 0, 0, 0, 0, 0, 0,
                                 0x00, 0x06, 0x00, 0x44, 0x00, 0x43, 0x00, 0x42, 0x00 };
  g_autoptr(GByteArray) rec = g_byte_array_new ();
  gsize start;

  put_record_header (rec, VFS495_REC_HANDSHAKE, sizeof (head) + VFS495_SSL_RANDOM_LEN + sizeof (tail));
  start = rec->len;
  g_byte_array_append (rec, head, sizeof (head));
  g_byte_array_append (rec, hs->client_random, VFS495_SSL_RANDOM_LEN);
  g_byte_array_append (rec, tail, sizeof (tail));
  g_byte_array_append (hs->msgs, rec->data + start, rec->len - start);
  return vfs495_tunnel (rec->data, rec->len);
}

GByteArray *
vfs495_handshake_flight (Vfs495Handshake *hs, Vfs495Ssl *ssl,
                         const guint8 *sh, gsize len,
                         const guint8 *modulus_le, gsize modulus_len,
                         const guint8 *pad, GError **error)
{
  static const guint8 ccs[] = { VFS495_REC_CCS, 3, 0, 0, 1, 1 };
  guint8 server_random[VFS495_SSL_RANDOM_LEN], keyblock[136];
  guint8 cke[4 + VFS495_RSA_LEN] = { 0x10, 0x00, 0x01, 0x00 };
  guint8 fin[4 + HS_FINISHED_LEN] = { 0x14, 0x00, 0x00, HS_FINISHED_LEN };
  g_autoptr(GByteArray) flight = g_byte_array_new ();
  g_autoptr(GByteArray) fin_rec = NULL;
  gsize shlen;

  if (len < 43 || sh[0] != VFS495_REC_HANDSHAKE || (shlen = (sh[3] << 8) | sh[4]) + 5 > len)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "no ServerHello from the sensor");
      return NULL;
    }
  memcpy (server_random, sh + 11, VFS495_SSL_RANDOM_LEN);
  g_byte_array_append (hs->msgs, sh + 5, shlen);   /* ServerHello + ServerHelloDone */

  if (!rsa_encrypt (modulus_le, modulus_len, hs->premaster, VFS495_SSL_PREMASTER_LEN, pad, cke + 4))
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "RSA key exchange failed");
      return NULL;
    }
  g_byte_array_append (hs->msgs, cke, sizeof (cke));

  ssl3_prf (hs->premaster, VFS495_SSL_PREMASTER_LEN, hs->client_random, server_random, hs->master, 48);
  ssl3_prf (hs->master, 48, server_random, hs->client_random, keyblock, sizeof (keyblock));
  memset (ssl, 0, sizeof (*ssl));
  memcpy (ssl->tx.mac, keyblock + 0, 20);
  memcpy (ssl->rx.mac, keyblock + 20, 20);
  memcpy (ssl->tx.key, keyblock + 40, 32);
  memcpy (ssl->rx.key, keyblock + 72, 32);
  memcpy (ssl->tx.iv, keyblock + 104, 16);
  memcpy (ssl->rx.iv, keyblock + 120, 16);

  ssl3_finished (hs->master, hs->msgs, label_clnt, fin + 4);
  fin_rec = vfs495_ssl_encrypt (ssl, VFS495_REC_HANDSHAKE, fin, sizeof (fin));

  put_record_header (flight, VFS495_REC_HANDSHAKE, sizeof (cke));
  g_byte_array_append (flight, cke, sizeof (cke));
  g_byte_array_append (flight, ccs, sizeof (ccs));
  g_byte_array_append (flight, fin_rec->data, fin_rec->len);
  return vfs495_tunnel (flight->data, flight->len);
}

gboolean
vfs495_handshake_verify (Vfs495Handshake *hs, Vfs495Ssl *ssl,
                         const guint8 *reply, gsize len, GError **error)
{
  guint8 want[HS_FINISHED_LEN];
  gboolean verified = FALSE;
  gsize p = 0;

  if (len >= 1 && reply[0] == VFS495_REC_ALERT)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "sensor alert %#x", reply[len - 1]);
      return FALSE;
    }
  ssl3_finished (hs->master, hs->msgs, label_srvr, want);
  while (p + 5 <= len)
    {
      guint8 type = reply[p];
      gsize n = (reply[p + 3] << 8) | reply[p + 4];
      g_autoptr(GByteArray) data = NULL;

      if (p + 5 + n > len)
        break;
      if (type != VFS495_REC_CCS)
        {
          data = g_byte_array_new ();
          if (!decrypt_one (ssl, type, reply + p + 5, n, data, error))
            return FALSE;
          if (type == VFS495_REC_HANDSHAKE)
            verified = data->len == 4 + HS_FINISHED_LEN && memcmp (data->data + 4, want, HS_FINISHED_LEN) == 0;
        }
      p += 5 + n;
    }
  if (!verified)
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "sensor Finished did not verify");
  return verified;
}
