/*
 * Assemble a raw swipe dump (VFS495_RAW / VFS_RAW .npy: n x 264 scrambled uint8) with the C port and
 * write a PGM. tests/test_assemble.sh compares it with tools/vfs495_assemble.py on the same lines.
 */
#include <stdio.h>
#include <string.h>

#include "../vfs495_assemble.h"

#define VFS495_LINE_WIDTH 264
#include "../vfs495_descramble.inc"

int
main (int argc, char **argv)
{
  g_autofree gchar *data = NULL;
  g_autofree guint8 *lines = NULL, *img = NULL;
  gsize len, hdr, n;
  guint h;
  Vfs495AsmStats st;
  gint64 t0;
  FILE *f;

  if (argc != 3 || !g_file_get_contents (argv[1], &data, &len, NULL) || len < 10 ||
      memcmp (data, "\x93NUMPY", 6) != 0)
    return 2;
  hdr = 10 + (guint8) data[8] + ((guint8) data[9] << 8);
  n = (len - hdr) / VFS495_LINE_WIDTH;
  lines = g_new (guint8, n * VFS495_LINE_WIDTH);
  for (gsize t = 0; t < n; t++)
    for (guint i = 0; i < VFS495_LINE_WIDTH; i++)
      lines[t * VFS495_LINE_WIDTH + vfs495_descramble[i]] = data[hdr + t * VFS495_LINE_WIDTH + i];

  t0 = g_get_monotonic_time ();
  img = vfs495_assemble (lines, n, &h, &st);
  fprintf (stderr, "%zu lines: %u moving, median lag %.1f, %.0f %% at the lag floor, %.0f rows\n",
           n, st.moving, st.median_lag, 100 * st.floor_frac, st.rows);
  if (!img)
    return 1;
  fprintf (stderr, "%zu lines -> %dx%u in %.2f s\n", n, VFS495_ASM_WIDTH, h, (g_get_monotonic_time () - t0) / 1e6);
  f = fopen (argv[2], "wb");
  fprintf (f, "P5\n%d %u\n255\n", VFS495_ASM_WIDTH, h);
  fwrite (img, 1, VFS495_ASM_WIDTH * h, f);
  fclose (f);
  return 0;
}
