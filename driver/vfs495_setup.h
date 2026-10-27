/*
 * Validity VFS495: the sensor's init/setup commands, loaded from a local file.
 *
 * HP's firmware patches and setup commands cannot be shipped with the driver. They are recorded once
 * per device from a trace of HP's binary and packed by tools/make_setup_bin.py; the format is
 * documented there. Pure GLib, so it can be tested outside libfprint (tests/test_setup.c).
 */
#pragma once

#include <glib.h>

#define VFS495_SETUP_PATH      "/var/lib/vfs495/setup.bin"
#define VFS495_SETUP_ARMING    0x01   /* flags: carries the image key + IV */

typedef struct
{
  guint8  flags;
  gsize   key_off;                    /* arming only: AES-256 key (32 B) here, IV (16 B) right after it */
  GBytes *cmd;
  GArray *reads;                      /* guint32: ep 0x82 read sizes after the reply */
} Vfs495SetupCmd;

typedef struct
{
  GPtrArray *init;                    /* GBytes: plaintext commands before the session */
  GPtrArray *setup;                   /* Vfs495SetupCmd: encrypted commands before each swipe */
} Vfs495Setup;

gssize       vfs495_config_key_offset (const guint8 *cmd,
                                       gsize         len);
Vfs495Setup *vfs495_setup_parse (const guint8 *data,
                                 gsize         len,
                                 GError      **error);
Vfs495Setup *vfs495_setup_load (const char *path,
                                GError    **error);
void         vfs495_setup_free (Vfs495Setup *setup);

G_DEFINE_AUTOPTR_CLEANUP_FUNC (Vfs495Setup, vfs495_setup_free)
