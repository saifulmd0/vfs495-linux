/*
 * Validity VFS495 (138a:003f) fingerprint reader driver for libfprint
 *
 * Copyright (C) 2026  (reverse-engineered from HP's Validity 4.5-136 Linux driver)
 *
 * This library is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License, version 2.1 or later.
 *
 * STATUS (see PLAN.md): open/close run the sensor's init sequence and SSLv3 session (port of
 * tools/ssl_session.py, verified byte-exact offline by tests/test_ssl.sh); activation runs the capture
 * loop (port of tools/vfs495_native_capture.py); vfs495_assemble.c turns a swipe into an image
 * (port of tools/vfs495_assemble.py, pixel-identical on recorded swipes). Modeled on the vfs5011/vfs301 sibling drivers.
 */

#define FP_COMPONENT "vfs495"

#include "drivers_api.h"
#include "vfs495_proto.h"
#include "vfs495_setup.h"
#include "vfs495_ssl.h"
#include "vfs495_assemble.h"

#include <fcntl.h>
#include <glib/gstdio.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

struct _FpDeviceVfs495
{
  FpImageDevice   parent;

  Vfs495Setup    *setup;          /* init/setup commands (VFS495_SETUP_PATH) */
  Vfs495Ssl       ssl;
  Vfs495Handshake hs;
  gboolean        session_open;
  guint           init_idx;       /* next init command */
  GBytes         *flash;          /* the 4 KiB flash block (storage table) */
  GByteArray     *reply;          /* last reply read by recv_buf () */

  /* capture loop */
  gboolean        loop_running;
  gboolean        deactivating;
  gboolean        activated;      /* activate_complete () sent */
  gboolean        finger_on;
  guint           setup_idx, read_idx;
  guint8          image_key[32], image_iv[16];
  EVP_CIPHER_CTX *image_cipher;   /* the swipe stream: one AES-256-CBC stream */
  GByteArray     *stream;         /* decrypted bytes not yet split into frames */
  GPtrArray      *lines;          /* raw (scrambled) 264 B lines of the current swipe */
  gint64          stream_start;
  double          peak;
  guint           quiet, seq_gaps, bad_frames;
  guint8          last_seq;
};
G_DECLARE_FINAL_TYPE (FpDeviceVfs495, fpi_device_vfs495, FPI, DEVICE_VFS495,
                      FpImageDevice)
G_DEFINE_TYPE (FpDeviceVfs495, fpi_device_vfs495, FP_TYPE_IMAGE_DEVICE)

#include "vfs495_descramble.inc"

static guint16 vfs495_unscramble[VFS495_LINE_WIDTH];   /* descrambled column -> raw position */

/* ---------------------------------------------------------------------------
 * USB helpers: every exchange is one SSM state that sends, one that reads into
 * self->reply, then a state that looks at the reply.
 * ------------------------------------------------------------------------- */
#define CMD_TIMEOUT   3000
#define INIT_PAUSE_DEFAULT 30 /* ms between init commands: back to back, the sensor resets.
                               * Env VFS495_INIT_PAUSE_MS overrides. */
#define REPLY_SMALL   0x400   /* init + handshake replies */
#define REPLY_LARGE   0x4000  /* encrypted command replies (the sensor ends them with a short packet) */

static void
send_buf (FpiSsm *ssm, FpDevice *dev, const guint8 *data, gsize len)
{
  FpiUsbTransfer *t = fpi_usb_transfer_new (dev);

  t->ssm = ssm;
  t->short_is_error = TRUE;
  fpi_usb_transfer_fill_bulk_full (t, VFS495_EP_CMD_OUT, g_memdup2 (data, len), len, g_free);
  fpi_usb_transfer_submit (t, CMD_TIMEOUT, NULL, fpi_ssm_usb_transfer_cb, NULL);
}

static void
send_array (FpiSsm *ssm, FpDevice *dev, GByteArray *data)
{
  send_buf (ssm, dev, data->data, data->len);
  g_byte_array_unref (data);
}

static void
recv_cb (FpiUsbTransfer *t, FpDevice *dev, gpointer user_data, GError *error)
{
  FpDeviceVfs495 *self = FPI_DEVICE_VFS495 (dev);

  if (error)
    {
      fpi_ssm_mark_failed (t->ssm, error);
      return;
    }
  g_clear_pointer (&self->reply, g_byte_array_unref);
  self->reply = g_byte_array_sized_new (t->actual_length);
  g_byte_array_append (self->reply, t->buffer, t->actual_length);
  fpi_ssm_next_state (t->ssm);
}

static void
recv_buf (FpiSsm *ssm, FpDevice *dev, guint8 ep, gsize len, guint timeout)
{
  FpiUsbTransfer *t = fpi_usb_transfer_new (dev);

  t->ssm = ssm;
  fpi_usb_transfer_fill_bulk (t, ep, len);
  fpi_usb_transfer_submit (t, timeout, NULL, recv_cb, NULL);
}

static void
random_bytes (guint8 *out, gsize len, gboolean nonzero)
{
  RAND_bytes (out, len);
  for (gsize i = 0; nonzero && i < len; i++)
    while (out[i] == 0)
      RAND_bytes (out + i, 1);
}

/* ---------------------------------------------------------------------------
 * Open: init sequence (plaintext), then the SSLv3 session. tools/ssl_session.py
 * ------------------------------------------------------------------------- */
enum open_states {
  OPEN_INIT_PAUSE,
  OPEN_INIT_SEND,
  OPEN_INIT_RECV,
  OPEN_INIT_CHECK,
  OPEN_UNLOAD_PAUSE,      /* patches still loaded: 1a UnloadPatch, like HP */
  OPEN_UNLOAD_SEND,
  OPEN_UNLOAD_RECV,
  OPEN_UNLOAD_DONE,
  OPEN_FLASH_RECV,        /* 1f SPI flash read: the data follows on ep 0x82 */
  OPEN_FLASH_DONE,
  OPEN_HELLO_SEND,
  OPEN_HELLO_RECV,
  OPEN_FLIGHT_SEND,
  OPEN_FLIGHT_RECV,
  OPEN_FLIGHT_CHECK,
  OPEN_VERSION_SEND,
  OPEN_VERSION_RECV,
  OPEN_VERSION_CHECK,
  OPEN_NUM_STATES,
};

static GBytes *
init_cmd (FpDeviceVfs495 *self)
{
  return g_ptr_array_index (self->setup->init, self->init_idx);
}

/* Pause between init commands (back to back, the sensor resets). VFS495_INIT_PAUSE_MS overrides the
 * default; lower it only on a known-good sensor, as a too-short pause makes the sensor reset mid-init. */
static guint
init_pause_ms (void)
{
  static gint ms = -1;

  if (ms < 0)
    {
      const char *e = g_getenv ("VFS495_INIT_PAUSE_MS");

      ms = e ? (gint) g_ascii_strtoll (e, NULL, 10) : INIT_PAUSE_DEFAULT;
      ms = CLAMP (ms, 0, 5000);
    }
  return ms;
}

static void
open_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpDeviceVfs495 *self = FPI_DEVICE_VFS495 (dev);
  g_autoptr(GError) error = NULL;
  const guint8 *cmd;
  gsize cmdlen;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case OPEN_INIT_PAUSE:
      if (self->init_idx >= self->setup->init->len)
        fpi_ssm_jump_to_state (ssm, OPEN_HELLO_SEND);
      else if (init_pause_ms () > 0)
        fpi_ssm_next_state_delayed (ssm, init_pause_ms ());
      else
        fpi_ssm_next_state (ssm);
      break;

    case OPEN_INIT_SEND:
      cmd = g_bytes_get_data (init_cmd (self), &cmdlen);
      send_buf (ssm, dev, cmd, cmdlen);
      break;

    case OPEN_INIT_RECV:
      recv_buf (ssm, dev, VFS495_EP_CMD_IN, REPLY_SMALL, CMD_TIMEOUT);
      break;

    case OPEN_INIT_CHECK:
      cmd = g_bytes_get_data (init_cmd (self), &cmdlen);
      if (self->reply->len >= 1 && self->reply->data[0] == VFS495_REC_ALERT)
        {
          /* still in a session from an earlier process: the sensor resets itself and re-enumerates */
          fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                              "sensor held a stale session and is resetting; try again"));
          return;
        }
      if (cmd[0] == VFS495_CMD_GET_VERSION && self->reply->len > 17 && self->reply->data[17] && !self->flash)
        fpi_ssm_jump_to_state (ssm, OPEN_UNLOAD_PAUSE);
      else if (cmd[0] == VFS495_CMD_SPI_BULK_READ && cmdlen >= 9)
        fpi_ssm_jump_to_state (ssm, OPEN_FLASH_RECV);
      else
        {
          self->init_idx++;
          fpi_ssm_jump_to_state (ssm, OPEN_INIT_PAUSE);
        }
      break;

    case OPEN_UNLOAD_PAUSE:
      fp_dbg ("patches still loaded: unloading first");
      fpi_ssm_next_state_delayed (ssm, MAX (init_pause_ms (), 1));
      break;

    case OPEN_UNLOAD_SEND:
      send_buf (ssm, dev, (const guint8 *) "\x1a", 1);
      break;

    case OPEN_UNLOAD_RECV:
      recv_buf (ssm, dev, VFS495_EP_CMD_IN, REPLY_SMALL, CMD_TIMEOUT);
      break;

    case OPEN_UNLOAD_DONE:
      self->init_idx++;
      fpi_ssm_jump_to_state (ssm, OPEN_INIT_PAUSE);
      break;

    case OPEN_FLASH_RECV:
      /* read exactly the requested size (u32 at offset 5): the sensor sends full packets, no short one */
      cmd = g_bytes_get_data (init_cmd (self), &cmdlen);
      recv_buf (ssm, dev, VFS495_EP_DATA_IN, cmd[5] | (cmd[6] << 8) | (cmd[7] << 16) | ((guint32) cmd[8] << 24), 1000);
      break;

    case OPEN_FLASH_DONE:
      if (self->reply->len == 0x1000)
        {
          g_clear_pointer (&self->flash, g_bytes_unref);
          self->flash = g_bytes_new (self->reply->data, self->reply->len);
        }
      self->init_idx++;
      fpi_ssm_jump_to_state (ssm, OPEN_INIT_PAUSE);
      break;

    case OPEN_HELLO_SEND:
      {
        guint8 client_random[VFS495_SSL_RANDOM_LEN], premaster[VFS495_SSL_PREMASTER_LEN];

        if (!self->flash)
          {
            fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                                "init read no flash block (setup file incomplete?)"));
            return;
          }
        random_bytes (client_random, sizeof (client_random), FALSE);
        random_bytes (premaster, sizeof (premaster), FALSE);
        vfs495_handshake_clear (&self->hs);
        vfs495_handshake_init (&self->hs, client_random, premaster);
        send_array (ssm, dev, vfs495_handshake_hello (&self->hs));
      }
      break;

    case OPEN_HELLO_RECV:
      recv_buf (ssm, dev, VFS495_EP_CMD_IN, REPLY_SMALL, CMD_TIMEOUT);
      break;

    case OPEN_FLIGHT_SEND:
      {
        g_autoptr(GBytes) modulus = vfs495_flash_storage (g_bytes_get_data (self->flash, NULL),
                                                          g_bytes_get_size (self->flash), 10);
        guint8 pad[VFS495_RSA_LEN - 3 - VFS495_SSL_PREMASTER_LEN];
        GByteArray *flight;

        if (!modulus)
          {
            fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                                "RSA key (storage id 10) not found in sensor flash"));
            return;
          }
        random_bytes (pad, sizeof (pad), TRUE);
        flight = vfs495_handshake_flight (&self->hs, &self->ssl, self->reply->data, self->reply->len,
                                          g_bytes_get_data (modulus, NULL), g_bytes_get_size (modulus),
                                          pad, &error);
        if (!flight)
          {
            fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "%s", error->message));
            return;
          }
        send_array (ssm, dev, flight);
      }
      break;

    case OPEN_FLIGHT_RECV:
      recv_buf (ssm, dev, VFS495_EP_CMD_IN, REPLY_SMALL, CMD_TIMEOUT);
      break;

    case OPEN_FLIGHT_CHECK:
      if (!vfs495_handshake_verify (&self->hs, &self->ssl, self->reply->data, self->reply->len, &error))
        {
          fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "handshake: %s", error->message));
          return;
        }
      vfs495_handshake_clear (&self->hs);
      self->session_open = TRUE;
      fp_dbg ("secure session open, sensor Finished verified");
      fpi_ssm_next_state (ssm);
      break;

    case OPEN_VERSION_SEND:
      send_array (ssm, dev, vfs495_ssl_encrypt (&self->ssl, VFS495_REC_APPDATA, (const guint8 *) "\x01", 1));
      break;

    case OPEN_VERSION_RECV:
      recv_buf (ssm, dev, VFS495_EP_CMD_IN, REPLY_LARGE, CMD_TIMEOUT);
      break;

    case OPEN_VERSION_CHECK:
      {
        g_autoptr(GByteArray) plain = vfs495_ssl_decrypt (&self->ssl, self->reply->data, self->reply->len,
                                                          NULL, &error);
        if (!plain || plain->len < 2 || plain->data[0] || plain->data[1])
          {
            fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "encrypted GetVersion failed%s%s",
                                                                error ? ": " : "", error ? error->message : ""));
            return;
          }
        fp_dbg ("encrypted GetVersion ok (%u B reply)", plain->len);
        fpi_ssm_mark_completed (ssm);
      }
      break;
    }
}

static void
release_usb (FpDeviceVfs495 *self)
{
  g_clear_pointer (&self->image_cipher, EVP_CIPHER_CTX_free);
  g_clear_pointer (&self->stream, g_byte_array_unref);
  g_clear_pointer (&self->lines, g_ptr_array_unref);
  g_usb_device_release_interface (fpi_device_get_usb_device (FP_DEVICE (self)), 0, 0, NULL);
  g_clear_pointer (&self->setup, vfs495_setup_free);
  g_clear_pointer (&self->flash, g_bytes_unref);
  g_clear_pointer (&self->reply, g_byte_array_unref);
  vfs495_handshake_clear (&self->hs);
  self->session_open = FALSE;
}

static void
open_complete (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpDeviceVfs495 *self = FPI_DEVICE_VFS495 (dev);

  if (error)
    release_usb (self);
  fpi_image_device_open_complete (FP_IMAGE_DEVICE (dev), error);
}

static void
dev_open (FpImageDevice *dev)
{
  GError *error = NULL;
  FpDeviceVfs495 *self = FPI_DEVICE_VFS495 (dev);
  GUsbDevice *usb = fpi_device_get_usb_device (FP_DEVICE (dev));
  const char *path = g_getenv ("VFS495_SETUP") ?: VFS495_SETUP_PATH;

  /* HP's per-device patches + setup commands, recorded once (tools/make_setup_bin.py) */
  self->setup = vfs495_setup_load (path, &error);
  if (!self->setup)
    {
      if (g_error_matches (error, G_FILE_ERROR, G_FILE_ERROR_NOENT))
        g_prefix_error (&error, "no setup file for this sensor yet, create it once with vfs495-setup: ");
      g_prefix_error (&error, "%s: ", path);
      fpi_image_device_open_complete (dev, error);
      return;
    }
  {
    GStatBuf st;

    /* per-device firmware patches + session commands: root only */
    if (g_stat (path, &st) == 0 && (st.st_mode & 077))
      fp_warn ("%s is readable by other users (mode %03o); it should be 0600 root", path, st.st_mode & 0777);
  }
  fp_dbg ("setup: %u init + %u setup commands from %s",
          self->setup->init->len, self->setup->setup->len, path);

  if (!g_usb_device_claim_interface (usb, 0, 0, &error))
    {
      g_clear_pointer (&self->setup, vfs495_setup_free);
      fpi_image_device_open_complete (dev, error);
      return;
    }

  self->init_idx = 0;
  self->image_cipher = EVP_CIPHER_CTX_new ();
  self->stream = g_byte_array_new ();
  self->lines = g_ptr_array_new_with_free_func (g_free);
  fpi_ssm_start (fpi_ssm_new (FP_DEVICE (dev), open_run_state, OPEN_NUM_STATES), open_complete);
}

/* ---------------------------------------------------------------------------
 * Close: encrypted close_notify (01 00), like HP on exit. Without it the sensor keeps the session
 * and resets itself on the next open (a re-enumeration). Errors here are not fatal.
 * ------------------------------------------------------------------------- */
enum close_states {
  CLOSE_SEND,
  CLOSE_RECV,
  CLOSE_CHECK,
  CLOSE_NUM_STATES,
};

static void
close_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpDeviceVfs495 *self = FPI_DEVICE_VFS495 (dev);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case CLOSE_SEND:
      if (!self->session_open)
        {
          fpi_ssm_mark_completed (ssm);
          return;
        }
      send_array (ssm, dev, vfs495_ssl_encrypt (&self->ssl, VFS495_REC_ALERT, (const guint8 *) "\x01\x00", 2));
      break;

    case CLOSE_RECV:
      recv_buf (ssm, dev, VFS495_EP_CMD_IN, REPLY_SMALL, 1000);
      break;

    case CLOSE_CHECK:
      {
        g_autoptr(GByteArray) plain = NULL;
        guint8 type = 0;

        plain = vfs495_ssl_decrypt (&self->ssl, self->reply->data, self->reply->len, &type, NULL);
        fp_dbg ("session closed: %s", plain && type == VFS495_REC_ALERT ? "sensor confirmed" : "NOT confirmed");
        fpi_ssm_mark_completed (ssm);
      }
      break;
    }
}

static void
close_complete (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  if (error)
    fp_dbg ("close_notify failed: %s", error->message);
  g_clear_error (&error);
  release_usb (FPI_DEVICE_VFS495 (dev));
  fpi_image_device_close_complete (FP_IMAGE_DEVICE (dev), NULL);
}

static void
dev_close (FpImageDevice *dev)
{
  fpi_ssm_start (fpi_ssm_new (FP_DEVICE (dev), close_run_state, CLOSE_NUM_STATES), close_complete);
}

/* ---------------------------------------------------------------------------
 * Capture loop, one swipe per run (tools/vfs495_native_capture.py):
 * setup commands with a fresh image key -> poll 17 until a finger is on ->
 * stream + decrypt the swipe from ep 0x82 -> 04 abort, drain, resync -> image.
 * ------------------------------------------------------------------------- */
#define FRAME_LEN        (VFS495_LINE_HDR + VFS495_LINE_WIDTH)   /* 272 B decrypted frame */
#define STREAM_CHUNK     16384
#define STREAM_TIMEOUT   150     /* ms; the sensor ends the stream ~0.4 s after the finger leaves */
#define MAX_SWIPE_US     (4 * G_USEC_PER_SEC)
#define QUIET_LINES      300     /* backup end rule: this many lines below QUIET_FRAC x peak energy */
#define QUIET_FRAC       0.1
#define FINGER_POLL_MS   50
#define MIN_LINES        400     /* fewer decoded lines = no usable swipe */
#define VFS495_MIN_ROWS_DEFAULT  80  /* shorter assembled prints are retried; env VFS495_MIN_ROWS overrides */
/* Too fast: the finger crossed the two sensor rows in fewer lines than the lag search can resolve, so
 * the speed is underestimated and the print comes out short and smeared. Measured (PLAN.md phase 7):
 * normal swipes <= 2 % of the moving lines at the lag floor; fast ones that still matched 10 %;
 * fast ones that matched nothing (score <= 15) 40-89 %. */
#define FAST_FLOOR_FRAC  0.25

/* Minimum assembled image rows; shorter prints are retried. The bridge exposes this as VFS_MIN_ROWS;
 * mirror it in the native driver with VFS495_MIN_ROWS (default 80). */
static guint
min_rows (void)
{
  static gint n = -1;

  if (n < 0)
    {
      const char *e = g_getenv ("VFS495_MIN_ROWS");

      n = e ? (gint) g_ascii_strtoll (e, NULL, 10) : VFS495_MIN_ROWS_DEFAULT;
      n = CLAMP (n, 0, 10000);
    }
  return n;
}

enum capture_states {
  CAP_SETUP_SEND,
  CAP_SETUP_RECV,
  CAP_SETUP_CHECK,
  CAP_SETUP_DATA,          /* ep 0x82 reads that follow some setup replies (calibration data) */
  CAP_SETUP_DATA_DONE,
  CAP_FINGER_SEND,         /* 17 GetFingerState: byte 2 bit 1 = finger */
  CAP_FINGER_RECV,
  CAP_FINGER_CHECK,
  CAP_STREAM,
  CAP_ABORT_SEND,          /* 04 AbortFingerprint */
  CAP_DRAIN,
  CAP_ABORT_RECV,
  CAP_ABORT_CHECK,
  CAP_NUM_STATES,
};

static Vfs495SetupCmd *
setup_cmd (FpDeviceVfs495 *self)
{
  return g_ptr_array_index (self->setup->setup, self->setup_idx);
}

static void
send_encrypted (FpiSsm *ssm, FpDevice *dev, const guint8 *payload, gsize len)
{
  FpDeviceVfs495 *self = FPI_DEVICE_VFS495 (dev);

  send_array (ssm, dev, vfs495_ssl_encrypt (&self->ssl, VFS495_REC_APPDATA, payload, len));
}

/* Ridge contrast of one line: mean |difference| of neighbouring main-image pixels. */
static double
line_energy (const guint8 *px)
{
  guint sum = 0;

  for (guint x = 0; x + 1 < VFS495_IMAGE_WIDTH; x++)
    sum += abs ((int) px[vfs495_unscramble[x + 1]] - (int) px[vfs495_unscramble[x]]);
  return (double) sum / (VFS495_IMAGE_WIDTH - 1);
}

/* Decrypted stream -> 272 B frames; keep the 264 raw (scrambled) pixels of each 01 fe frame.
 * The stream ends with one 01 01 trailer frame (byte 3 = line count / 256). The first 16 lines are
 * buffered from before the finger was detected; the line counter jumps after them (one "gap").
 * Returns FALSE at the trailer, or when the backup end rule says the finger is gone. */
static gboolean
take_frames (FpDeviceVfs495 *self)
{
  gsize p = 0;

  for (; p + FRAME_LEN <= self->stream->len; p += FRAME_LEN)
    {
      const guint8 *f = self->stream->data + p;
      double e;

      if (f[0] == 0x01 && f[1] == 0x01)
        {
          fp_dbg ("end of stream after %u lines (trailer %02x)", self->lines->len, f[3]);
          g_byte_array_set_size (self->stream, 0);
          return FALSE;
        }
      if (f[0] != 0x01 || f[1] != 0xfe)
        {
          fp_dbg ("non-image frame after line %u: %02x %02x %02x %02x %02x %02x %02x %02x",
                  self->lines->len, f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7]);
          self->bad_frames++;
          continue;
        }
      if (self->lines->len && (guint8) (f[2] - self->last_seq) != 1)
        {
          fp_dbg ("sequence gap after line %u: %u -> %u", self->lines->len, self->last_seq, f[2]);
          self->seq_gaps++;
        }
      self->last_seq = f[2];
      g_ptr_array_add (self->lines, g_memdup2 (f + VFS495_LINE_HDR, VFS495_LINE_WIDTH));

      e = line_energy (f + VFS495_LINE_HDR);
      self->peak = MAX (self->peak, e);
      self->quiet = e < QUIET_FRAC * self->peak ? self->quiet + 1 : 0;
    }
  g_byte_array_remove_range (self->stream, 0, p);
  return !(self->lines->len > 2 * QUIET_LINES && self->quiet >= QUIET_LINES);
}

static void
stream_cb (FpiUsbTransfer *t, FpDevice *dev, gpointer user_data, GError *error)
{
  FpDeviceVfs495 *self = FPI_DEVICE_VFS495 (dev);
  int n = 0;

  if (error)
    {
      if (!g_error_matches (error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_TIMED_OUT))
        {
          fpi_ssm_mark_failed (t->ssm, error);
          return;
        }
      g_error_free (error);                         /* the sensor ended the stream: swipe over */
      fpi_ssm_next_state (t->ssm);
      return;
    }

  g_byte_array_set_size (self->stream, self->stream->len + t->actual_length);
  EVP_DecryptUpdate (self->image_cipher, self->stream->data + self->stream->len - t->actual_length, &n,
                     t->buffer, t->actual_length);
  g_byte_array_set_size (self->stream, self->stream->len - t->actual_length + n);

  if (!take_frames (self) || g_get_monotonic_time () - self->stream_start > MAX_SWIPE_US)
    fpi_ssm_next_state (t->ssm);
  else
    fpi_ssm_jump_to_state (t->ssm, CAP_STREAM);
}

static void
drain_cb (FpiUsbTransfer *t, FpDevice *dev, gpointer user_data, GError *error)
{
  if (error)                                        /* nothing left queued */
    {
      g_error_free (error);
      fpi_ssm_next_state (t->ssm);
    }
  else
    fpi_ssm_jump_to_state (t->ssm, CAP_DRAIN);
}

static void
abort_recv_cb (FpiUsbTransfer *t, FpDevice *dev, gpointer user_data, GError *error)
{
  FpDeviceVfs495 *self = FPI_DEVICE_VFS495 (dev);

  g_clear_pointer (&self->reply, g_byte_array_unref);
  self->reply = g_byte_array_new ();
  if (error)
    g_error_free (error);
  else
    g_byte_array_append (self->reply, t->buffer, t->actual_length);
  fpi_ssm_next_state (t->ssm);
}

static void
capture_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpImageDevice *idev = FP_IMAGE_DEVICE (dev);
  FpDeviceVfs495 *self = FPI_DEVICE_VFS495 (dev);
  g_autoptr(GError) error = NULL;
  FpiUsbTransfer *t;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case CAP_SETUP_SEND:
      {
        Vfs495SetupCmd *c;
        const guint8 *data;
        gsize len;
        g_autofree guint8 *cmd = NULL;

        if (self->setup_idx >= self->setup->setup->len)
          {
            /* armed: the sensor waits for a finger now */
            if (!self->activated)
              {
                self->activated = TRUE;
                fpi_image_device_activate_complete (idev, NULL);
              }
            fpi_ssm_jump_to_state (ssm, CAP_FINGER_SEND);
            return;
          }
        c = setup_cmd (self);
        data = g_bytes_get_data (c->cmd, &len);
        cmd = g_memdup2 (data, len);
        if (c->flags & VFS495_SETUP_ARMING)
          {
            /* the arming command carries the key the swipe stream is encrypted with: pick a fresh one */
            random_bytes (self->image_key, sizeof (self->image_key), FALSE);
            random_bytes (self->image_iv, sizeof (self->image_iv), FALSE);
            memcpy (cmd + c->key_off, self->image_key, sizeof (self->image_key));
            memcpy (cmd + c->key_off + sizeof (self->image_key), self->image_iv, sizeof (self->image_iv));
          }
        send_encrypted (ssm, dev, cmd, len);
      }
      break;

    case CAP_SETUP_RECV:
      recv_buf (ssm, dev, VFS495_EP_CMD_IN, REPLY_LARGE, CMD_TIMEOUT);
      break;

    case CAP_SETUP_CHECK:
      {
        g_autoptr(GByteArray) plain = vfs495_ssl_decrypt (&self->ssl, self->reply->data, self->reply->len,
                                                          NULL, &error);
        if (!plain || plain->len < 2 || plain->data[0] || plain->data[1])
          {
            fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                                "setup command %02x rejected%s%s",
                                                                ((const guint8 *) g_bytes_get_data (setup_cmd (self)->cmd, NULL))[0],
                                                                error ? ": " : "", error ? error->message : ""));
            return;
          }
        self->read_idx = 0;
        fpi_ssm_jump_to_state (ssm, setup_cmd (self)->reads->len ? CAP_SETUP_DATA : CAP_SETUP_DATA_DONE);
      }
      break;

    case CAP_SETUP_DATA:
      recv_buf (ssm, dev, VFS495_EP_DATA_IN,
                g_array_index (setup_cmd (self)->reads, guint32, self->read_idx), CMD_TIMEOUT);
      break;

    case CAP_SETUP_DATA_DONE:
      if (setup_cmd (self)->reads->len && ++self->read_idx < setup_cmd (self)->reads->len)
        {
          fpi_ssm_jump_to_state (ssm, CAP_SETUP_DATA);
          return;
        }
      self->setup_idx++;
      fpi_ssm_jump_to_state (ssm, CAP_SETUP_SEND);
      break;

    case CAP_FINGER_SEND:
      if (self->deactivating)
        {
          fpi_ssm_jump_to_state (ssm, CAP_ABORT_SEND);     /* disarm before leaving */
          return;
        }
      send_encrypted (ssm, dev, (const guint8 *) "\x17", 1);
      break;

    case CAP_FINGER_RECV:
      recv_buf (ssm, dev, VFS495_EP_CMD_IN, REPLY_LARGE, CMD_TIMEOUT);
      break;

    case CAP_FINGER_CHECK:
      {
        g_autoptr(GByteArray) plain = vfs495_ssl_decrypt (&self->ssl, self->reply->data, self->reply->len,
                                                          NULL, &error);
        if (!plain)
          {
            fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "%s", error->message));
            return;
          }
        if (plain->len <= 2 || !(plain->data[2] & 0x02))
          {
            fpi_ssm_jump_to_state_delayed (ssm, CAP_FINGER_SEND, FINGER_POLL_MS);
            return;
          }
        fp_dbg ("finger on");
        fpi_image_device_report_finger_status (idev, TRUE);
        self->finger_on = TRUE;

        EVP_CIPHER_CTX_reset (self->image_cipher);
        EVP_DecryptInit_ex (self->image_cipher, EVP_aes_256_cbc (), NULL, self->image_key, self->image_iv);
        EVP_CIPHER_CTX_set_padding (self->image_cipher, 0);
        g_byte_array_set_size (self->stream, 0);
        g_ptr_array_set_size (self->lines, 0);
        self->peak = 0;
        self->quiet = self->seq_gaps = self->bad_frames = 0;
        self->stream_start = g_get_monotonic_time ();
        fpi_ssm_next_state (ssm);
      }
      break;

    case CAP_STREAM:
      t = fpi_usb_transfer_new (dev);
      t->ssm = ssm;
      fpi_usb_transfer_fill_bulk (t, VFS495_EP_DATA_IN, STREAM_CHUNK);
      fpi_usb_transfer_submit (t, STREAM_TIMEOUT, NULL, stream_cb, NULL);
      break;

    case CAP_ABORT_SEND:
      send_encrypted (ssm, dev, (const guint8 *) "\x04", 1);
      break;

    case CAP_DRAIN:
      t = fpi_usb_transfer_new (dev);
      t->ssm = ssm;
      fpi_usb_transfer_fill_bulk (t, VFS495_EP_DATA_IN, STREAM_CHUNK);
      fpi_usb_transfer_submit (t, 300, NULL, drain_cb, NULL);
      break;

    case CAP_ABORT_RECV:
      t = fpi_usb_transfer_new (dev);
      t->ssm = ssm;
      fpi_usb_transfer_fill_bulk (t, VFS495_EP_CMD_IN, REPLY_SMALL);
      fpi_usb_transfer_submit (t, 1000, NULL, abort_recv_cb, NULL);
      break;

    case CAP_ABORT_CHECK:
      {
        /* consume the reply so the record sequence numbers stay in sync */
        g_autoptr(GByteArray) plain = vfs495_ssl_decrypt (&self->ssl, self->reply->data, self->reply->len, NULL, NULL);

        fpi_ssm_mark_completed (ssm);
      }
      break;
    }
}

/* Optional raw dump for offline tuning (VFS495_RAW=FILE.npy, or a directory: one swipe-NNN.npy per
 * swipe): the scrambled lines, same layout as vfs495_native_capture.py VFS_RAW. Biometric data: 0600. */
static void
dump_raw (FpDeviceVfs495 *self)
{
  static guint swipe_no;
  const char *raw = g_getenv ("VFS495_RAW");
  g_autofree gchar *path = NULL;
  g_autoptr(GByteArray) out = NULL;
  g_autofree gchar *hdr = NULL;
  gsize pad;

  if (!raw || !self->lines->len)
    return;
  swipe_no++;
  path = g_file_test (raw, G_FILE_TEST_IS_DIR) ? g_strdup_printf ("%s/swipe-%03u.npy", raw, swipe_no) : g_strdup (raw);
  hdr = g_strdup_printf ("{'descr': '|u1', 'fortran_order': False, 'shape': (%u, %d), }",
                         self->lines->len, VFS495_LINE_WIDTH);
  pad = 64 - (10 + strlen (hdr) + 1) % 64;
  out = g_byte_array_new ();
  g_byte_array_append (out, (const guint8 *) "\x93NUMPY\x01\x00", 8);
  g_byte_array_append (out, (const guint8 *) (guint16[]) { GUINT16_TO_LE (strlen (hdr) + pad + 1) }, 2);
  g_byte_array_append (out, (const guint8 *) hdr, strlen (hdr));
  for (gsize i = 0; i < pad; i++)
    g_byte_array_append (out, (const guint8 *) " ", 1);
  g_byte_array_append (out, (const guint8 *) "\n", 1);
  for (guint i = 0; i < self->lines->len; i++)
    g_byte_array_append (out, g_ptr_array_index (self->lines, i), VFS495_LINE_WIDTH);

  int fd = open (path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0 || write (fd, out->data, out->len) != (gssize) out->len)
    fp_warn ("could not write %s", path);
  if (fd >= 0)
    close (fd);
}

/* ---------------------------------------------------------------------------
 * Assembly runs in a worker thread (~1-2 s per swipe); the main loop stays responsive.
 * The task owns the swipe's lines; the device only sees the result.
 * ------------------------------------------------------------------------- */
typedef struct
{
  GPtrArray     *lines;          /* raw (scrambled) 264 B lines */
  guint8        *px;
  guint          height;
  Vfs495AsmStats stats;
} AssembleJob;

static void
assemble_job_free (AssembleJob *job)
{
  g_clear_pointer (&job->lines, g_ptr_array_unref);
  g_free (job->px);
  g_free (job);
}

static void
assemble_thread (GTask *task, gpointer source, gpointer task_data, GCancellable *cancellable)
{
  AssembleJob *job = task_data;
  g_autofree guint8 *lines = g_new (guint8, job->lines->len * VFS495_LINE_WIDTH);

  for (guint t = 0; t < job->lines->len; t++)
    {
      const guint8 *raw = g_ptr_array_index (job->lines, t);

      for (guint i = 0; i < VFS495_LINE_WIDTH; i++)
        lines[t * VFS495_LINE_WIDTH + vfs495_descramble[i]] = raw[i];   /* out[perm[i]] = raw[i] */
    }
  job->px = vfs495_assemble (lines, job->lines->len, &job->height, &job->stats);
  g_task_return_boolean (task, TRUE);
}

/* Image or retry, from the assembly result. */
static void
submit_image (FpDeviceVfs495 *self, AssembleJob *job)
{
  FpImageDevice *dev = FP_IMAGE_DEVICE (self);
  const Vfs495AsmStats *st = &job->stats;
  FpImage *img;

  fp_dbg ("assembly: %u moving lines, median lag %.1f, %.0f%% at the lag floor, %.0f rows",
          st->moving, st->median_lag, 100 * st->floor_frac, st->rows);
  if (st->floor_frac > FAST_FLOOR_FRAC)
    {
      fp_dbg ("swipe too fast");
      fpi_image_device_retry_scan (dev, FP_DEVICE_RETRY_TOO_FAST);
      return;
    }
  if (!job->px || job->height < min_rows ())
    {
      fp_dbg ("no usable print (%u rows)", job->height);
      fpi_image_device_retry_scan (dev, FP_DEVICE_RETRY_TOO_SHORT);
      return;
    }

  img = fp_image_new (VFS495_ASM_WIDTH, job->height);
  memcpy (img->data, job->px, VFS495_ASM_WIDTH * job->height);
  fp_dbg ("image %dx%u", VFS495_ASM_WIDTH, job->height);
  fpi_image_device_image_captured (dev, img);
}

static void start_capture (FpImageDevice *dev);

/* End of one loop run: finger-off after the image (libfprint expects that order), then the next swipe
 * or the deactivation / error the loop was waiting for. */
static void
capture_finish (FpDeviceVfs495 *self, GError *error)
{
  FpImageDevice *dev = FP_IMAGE_DEVICE (self);

  if (self->finger_on && !self->deactivating)
    fpi_image_device_report_finger_status (dev, FALSE);
  self->finger_on = FALSE;
  self->loop_running = FALSE;

  if (self->deactivating)
    fpi_image_device_deactivate_complete (dev, error);
  else if (error && !self->activated)
    fpi_image_device_activate_complete (dev, error);
  else if (error)
    fpi_image_device_session_error (dev, error);
  else
    start_capture (dev);
}

static void
assemble_done (GObject *source, GAsyncResult *res, gpointer user_data)
{
  FpDeviceVfs495 *self = FPI_DEVICE_VFS495 (source);
  AssembleJob *job = g_task_get_task_data (G_TASK (res));

  /* deactivation requested meanwhile: the image is no longer wanted */
  if (!self->deactivating)
    submit_image (self, job);
  capture_finish (self, NULL);
}

static void
capture_complete (FpiSsm *ssm, FpDevice *_dev, GError *error)
{
  FpDeviceVfs495 *self = FPI_DEVICE_VFS495 (_dev);

  if (!self->deactivating && !error && self->finger_on)
    {
      g_autoptr(GTask) task = NULL;
      AssembleJob *job;

      fp_dbg ("swipe: %u lines, %u sequence gaps, %u bad frames", self->lines->len, self->seq_gaps, self->bad_frames);
      dump_raw (self);
      if (self->lines->len < MIN_LINES)
        {
          fp_dbg ("no usable print (%u lines)", self->lines->len);
          fpi_image_device_retry_scan (FP_IMAGE_DEVICE (self), FP_DEVICE_RETRY_TOO_SHORT);
          capture_finish (self, NULL);
          return;
        }
      job = g_new0 (AssembleJob, 1);
      job->lines = g_steal_pointer (&self->lines);
      self->lines = g_ptr_array_new_with_free_func (g_free);
      task = g_task_new (self, NULL, assemble_done, NULL);
      g_task_set_task_data (task, job, (GDestroyNotify) assemble_job_free);
      g_task_run_in_thread (task, assemble_thread);     /* loop_running stays TRUE until assemble_done */
      return;
    }
  capture_finish (self, error);
}

static void
start_capture (FpImageDevice *dev)
{
  FpDeviceVfs495 *self = FPI_DEVICE_VFS495 (dev);

  self->loop_running = TRUE;
  self->setup_idx = 0;
  fpi_ssm_start (fpi_ssm_new (FP_DEVICE (dev), capture_run_state, CAP_NUM_STATES), capture_complete);
}

static void
dev_activate (FpImageDevice *dev)
{
  FpDeviceVfs495 *self = FPI_DEVICE_VFS495 (dev);

  self->deactivating = FALSE;
  self->activated = FALSE;
  start_capture (dev);
}

static void
dev_deactivate (FpImageDevice *dev)
{
  FpDeviceVfs495 *self = FPI_DEVICE_VFS495 (dev);

  if (self->loop_running)
    self->deactivating = TRUE;      /* the loop disarms the sensor and completes */
  else
    fpi_image_device_deactivate_complete (dev, NULL);
}

static const FpIdEntry id_table[] = {
  { .vid = VFS495_VID, .pid = VFS495_PID, },
  { .vid = 0, .pid = 0, },
};

static void
fpi_device_vfs495_init (FpDeviceVfs495 *self)
{
}

static void
fpi_device_vfs495_class_init (FpDeviceVfs495Class *klass)
{
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);
  FpImageDeviceClass *img_class = FP_IMAGE_DEVICE_CLASS (klass);

  dev_class->id = "vfs495";
  dev_class->full_name = "Validity VFS495";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->id_table = id_table;
  dev_class->scan_type = FP_SCAN_TYPE_SWIPE;

  img_class->img_open = dev_open;
  img_class->img_close = dev_close;
  img_class->activate = dev_activate;
  img_class->deactivate = dev_deactivate;

  for (guint i = 0; i < VFS495_LINE_WIDTH; i++)
    vfs495_unscramble[vfs495_descramble[i]] = i;

  img_class->img_width = VFS495_IMAGE_WIDTH;
  img_class->img_height = -1;
}
