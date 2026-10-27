/*
 * Replay tests/ssl_vectors.py: the C session layer must put the same bytes on the wire as
 * tools/ssl_session.py (verified on hardware) and accept the simulated sensor's replies.
 */
#include <stdio.h>
#include <string.h>

#include "../vfs495_ssl.h"

static GKeyFile *kf;

static GBytes *
vec (const char *key)
{
  g_autofree gchar *hex = g_key_file_get_string (kf, "v", key, NULL);
  gsize n = strlen (hex) / 2;
  guint8 *b = g_malloc (n);

  for (gsize i = 0; i < n; i++)
    sscanf (hex + 2 * i, "%2hhx", &b[i]);
  return g_bytes_new_take (b, n);
}

static int failures;

static void
same (const char *what, GByteArray *got, const char *key)
{
  g_autoptr(GBytes) want = vec (key);

  if (got && got->len == g_bytes_get_size (want) && memcmp (got->data, g_bytes_get_data (want, NULL), got->len) == 0)
    printf ("ok   %s (%u B)\n", what, got->len);
  else
    {
      printf ("FAIL %s\n", what);
      failures++;
    }
}

#define D(b) g_bytes_get_data (b, NULL), g_bytes_get_size (b)

int
main (int argc, char **argv)
{
  g_autoptr(GError) error = NULL;
  Vfs495Handshake hs;
  Vfs495Ssl ssl;
  guint8 last;

  kf = g_key_file_new ();
  if (argc < 2 || !g_key_file_load_from_file (kf, argv[1], 0, NULL))
    return 2;

  g_autoptr(GBytes) modulus = vec ("modulus"), cr = vec ("client_random"), pm = vec ("premaster");
  g_autoptr(GBytes) pad = vec ("pad"), sh = vec ("server_hello"), fin = vec ("server_fin");
  g_autoptr(GBytes) reply = vec ("cmd_reply"), close_reply = vec ("close_reply"), flash = vec ("flash");

  g_autoptr(GBytes) key = vfs495_flash_storage (D (flash), 10);
  if (!key || !g_bytes_equal (key, modulus))
    {
      printf ("FAIL flash storage id 10\n");
      failures++;
    }
  else
    printf ("ok   flash storage id 10 = RSA modulus\n");

  vfs495_handshake_init (&hs, g_bytes_get_data (cr, NULL), g_bytes_get_data (pm, NULL));
  g_autoptr(GByteArray) hello = vfs495_handshake_hello (&hs);
  same ("ClientHello", hello, "hello");
  g_autoptr(GByteArray) flight = vfs495_handshake_flight (&hs, &ssl, D (sh), D (modulus),
                                                          g_bytes_get_data (pad, NULL), &error);
  same ("ClientKeyExchange + CCS + Finished", flight, "flight");
  if (vfs495_handshake_verify (&hs, &ssl, D (fin), &error))
    printf ("ok   sensor Finished verified\n");
  else
    {
      printf ("FAIL sensor Finished: %s\n", error->message);
      failures++;
      g_clear_error (&error);
    }
  vfs495_handshake_clear (&hs);

  g_autoptr(GByteArray) cmd = vfs495_ssl_encrypt (&ssl, VFS495_REC_APPDATA, (const guint8 *) "\x01", 1);
  same ("encrypted GetVersion", cmd, "cmd");
  g_autoptr(GByteArray) plain = vfs495_ssl_decrypt (&ssl, D (reply), &last, &error);
  same ("decrypted reply", plain, "cmd_plain");
  g_autoptr(GByteArray) cl = vfs495_ssl_encrypt (&ssl, VFS495_REC_ALERT, (const guint8 *) "\x01\x00", 2);
  same ("close_notify", cl, "close");
  g_autoptr(GByteArray) cr2 = vfs495_ssl_decrypt (&ssl, D (close_reply), &last, &error);
  if (cr2 && last == VFS495_REC_ALERT && cr2->len == 2 && cr2->data[0] == 1 && cr2->data[1] == 0)
    printf ("ok   sensor close_notify\n");
  else
    {
      printf ("FAIL sensor close_notify\n");
      failures++;
    }

  /* a tampered reply must fail the MAC */
  g_autoptr(GBytes) bad = vec ("cmd_reply");
  gsize n;
  guint8 *b = g_bytes_unref_to_data (g_steal_pointer (&bad), &n);
  b[n - 20] ^= 1;
  Vfs495Ssl ssl2 = ssl;
  g_autoptr(GByteArray) none = vfs495_ssl_decrypt (&ssl2, b, n, &last, NULL);
  printf ("%s tampered record rejected\n", none ? "FAIL" : "ok  ");
  failures += none != NULL;
  g_free (b);

  g_key_file_free (kf);
  printf (failures ? "%d FAILED\n" : "all ok\n", failures);
  return failures != 0;
}
