/*
 * Validity VFS495: parser for the setup file (format: tools/make_setup_bin.py).
 *
 * This library is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License, version 2.1 or later.
 */

#include <string.h>

#include "vfs495_setup.h"

#define MAGIC "VFS495S1"

typedef struct
{
  const guint8 *p;
  gsize         left;
} Reader;

static gboolean
take (Reader *r, gsize n, const guint8 **out)
{
  if (r->left < n)
    return FALSE;
  *out = r->p;
  r->p += n;
  r->left -= n;
  return TRUE;
}

static gboolean
take_u8 (Reader *r, guint8 *v)
{
  const guint8 *b;

  if (!take (r, 1, &b))
    return FALSE;
  *v = b[0];
  return TRUE;
}

static gboolean
take_u16 (Reader *r, guint16 *v)
{
  const guint8 *b;

  if (!take (r, 2, &b))
    return FALSE;
  *v = b[0] | (b[1] << 8);
  return TRUE;
}

static gboolean
take_u32 (Reader *r, guint32 *v)
{
  const guint8 *b;

  if (!take (r, 4, &b))
    return FALSE;
  *v = b[0] | (b[1] << 8) | (b[2] << 16) | ((guint32) b[3] << 24);
  return TRUE;
}

static GBytes *
take_cmd (Reader *r)
{
  const guint8 *b;
  guint32 n;

  if (!take_u32 (r, &n) || n == 0 || !take (r, n, &b))
    return NULL;
  return g_bytes_new (b, n);
}

static void
setup_cmd_free (gpointer data)
{
  Vfs495SetupCmd *c = data;

  g_bytes_unref (c->cmd);
  g_array_unref (c->reads);
  g_free (c);
}

void
vfs495_setup_free (Vfs495Setup *setup)
{
  if (!setup)
    return;
  g_ptr_array_unref (setup->init);
  g_ptr_array_unref (setup->setup);
  g_free (setup);
}

Vfs495Setup *
vfs495_setup_parse (const guint8 *data, gsize len, GError **error)
{
  g_autoptr(Vfs495Setup) s = g_new0 (Vfs495Setup, 1);
  Reader r = { data, len };
  const guint8 *magic;
  guint16 n_init, n_setup;
  guint arming = 0;

  s->init = g_ptr_array_new_with_free_func ((GDestroyNotify) g_bytes_unref);
  s->setup = g_ptr_array_new_with_free_func (setup_cmd_free);

  if (!take (&r, strlen (MAGIC), &magic) || memcmp (magic, MAGIC, strlen (MAGIC)) != 0)
    goto bad;

  if (!take_u16 (&r, &n_init))
    goto bad;
  for (guint i = 0; i < n_init; i++)
    {
      GBytes *cmd = take_cmd (&r);

      if (!cmd)
        goto bad;
      g_ptr_array_add (s->init, cmd);
    }

  if (!take_u16 (&r, &n_setup))
    goto bad;
  for (guint i = 0; i < n_setup; i++)
    {
      Vfs495SetupCmd *c = g_new0 (Vfs495SetupCmd, 1);
      guint16 n_reads;

      c->reads = g_array_new (FALSE, FALSE, sizeof (guint32));
      g_ptr_array_add (s->setup, c);
      if (!take_u8 (&r, &c->flags) || !(c->cmd = take_cmd (&r)) || !take_u16 (&r, &n_reads))
        goto bad;
      for (guint j = 0; j < n_reads; j++)
        {
          guint32 size;

          if (!take_u32 (&r, &size))
            goto bad;
          g_array_append_val (c->reads, size);
        }
      if (c->flags & VFS495_SETUP_ARMING)
        {
          gsize clen;
          const guint8 *cdata = g_bytes_get_data (c->cmd, &clen);
          gssize off = vfs495_config_key_offset (cdata, clen);

          if (off < 0)
            goto bad;
          c->key_off = off;
          arming++;
        }
    }

  if (r.left != 0 || arming != 1)
    goto bad;

  return g_steal_pointer (&s);

bad:
  g_set_error (error, G_FILE_ERROR, G_FILE_ERROR_INVAL,
               "VFS495 setup file is invalid (create it with tools/make_setup_bin.py)");
  return NULL;
}

/* Offset of the image key in an 02 config: the first 48 B (key + IV) of its type-6 TLV. The config is
 * a 5 B header and then u16le type, u16le length, payload. 2927 in HP's 3033 B arming command; a config
 * with TLVs removed (setup.bin --minimal) has it elsewhere. -1 if there is none or the TLVs don't parse. */
gssize
vfs495_config_key_offset (const guint8 *cmd, gsize len)
{
  gssize key = -1;
  gsize o = 5;

  if (len < 5 || cmd[0] != 0x02)
    return -1;
  while (o < len)
    {
      guint16 type, n;

      if (len - o < 4)
        return -1;
      type = cmd[o] | cmd[o + 1] << 8;
      n = cmd[o + 2] | cmd[o + 3] << 8;
      if (len - o - 4 < n)
        return -1;
      if (type == 6 && n >= 48 && key < 0)
        key = o + 4;
      o += 4 + n;
    }
  return key;
}

Vfs495Setup *
vfs495_setup_load (const char *path, GError **error)
{
  g_autofree gchar *data = NULL;
  gsize len;

  if (!g_file_get_contents (path, &data, &len, error))
    return NULL;
  return vfs495_setup_parse ((const guint8 *) data, len, error);
}
