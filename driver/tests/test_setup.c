/*
 * Dump a VFS495 setup file the way the driver parses it, one command per line:
 *   init <n> <len> <sha256>
 *   setup <n> <flags> <len> <sha256> <read sizes...> [key=<offset of the image key, arming only>]
 * tests/test_setup.sh compares this with the same dump made from the JSON files in Python.
 * With --corrupt: also check that every truncation and a flipped magic are rejected.
 */
#include <stdio.h>
#include <string.h>

#include "../vfs495_setup.h"

static void
dump (const char *tag, guint i, guint8 flags, gsize key_off, GBytes *cmd, GArray *reads)
{
  g_autofree gchar *sum = g_compute_checksum_for_bytes (G_CHECKSUM_SHA256, cmd);

  if (reads == NULL)
    printf ("%s %u %zu %s\n", tag, i, g_bytes_get_size (cmd), sum);
  else
    {
      printf ("%s %u %u %zu %s", tag, i, flags, g_bytes_get_size (cmd), sum);
      for (guint j = 0; j < reads->len; j++)
        printf (" %u", g_array_index (reads, guint32, j));
      if (flags & VFS495_SETUP_ARMING)
        printf (" key=%zu", key_off);
      printf ("\n");
    }
}

int
main (int argc, char **argv)
{
  g_autoptr(GError) error = NULL;
  g_autoptr(Vfs495Setup) s = NULL;
  g_autofree gchar *data = NULL;
  gsize len;

  if (argc < 2)
    return 2;
  s = vfs495_setup_load (argv[1], &error);
  if (!s)
    {
      fprintf (stderr, "%s\n", error->message);
      return 1;
    }
  for (guint i = 0; i < s->init->len; i++)
    dump ("init", i, 0, 0, g_ptr_array_index (s->init, i), NULL);
  for (guint i = 0; i < s->setup->len; i++)
    {
      Vfs495SetupCmd *c = g_ptr_array_index (s->setup, i);
      dump ("setup", i, c->flags, c->key_off, c->cmd, c->reads);
    }

  if (argc > 2 && strcmp (argv[2], "--corrupt") == 0)
    {
      g_file_get_contents (argv[1], &data, &len, NULL);
      for (gsize n = 0; n < len; n++)
        {
          Vfs495Setup *t = vfs495_setup_parse ((const guint8 *) data, n, NULL);
          if (t)
            {
              fprintf (stderr, "truncated file (%zu of %zu B) was accepted\n", n, len);
              return 1;
            }
        }
      data[0] ^= 0xff;
      if (vfs495_setup_parse ((const guint8 *) data, len, NULL))
        {
          fprintf (stderr, "bad magic was accepted\n");
          return 1;
        }
      fprintf (stderr, "all %zu truncations and a bad magic rejected\n", len);
    }
  return 0;
}
