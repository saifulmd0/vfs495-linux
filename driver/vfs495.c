/*
 * Validity VFS495 (138a:003f) fingerprint reader driver for libfprint
 *
 * Copyright (C) 2026  (reverse-engineered from HP's Validity 4.5-136 Linux driver)
 *
 * This library is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License, version 2.1 or later.
 *
 * STATUS: scaffold. The device lifecycle, DLI line decode + column descramble,
 * and swipe assembly are implemented from the reverse-engineered protocol. The
 * sensor unlock (RAM patch upload + SSLv3 control session) is stubbed with the
 * decoded steps as TODOs -- see vfs495-re/NOTES.md ("REMAINING TO A DRIVER").
 * Modeled on the vfs5011/vfs301 sibling drivers.
 */

#define FP_COMPONENT "vfs495"

#include "drivers_api.h"
#include "vfs495_proto.h"

struct _FpDeviceVfs495
{
  FpImageDevice parent;

  guint8       *capture_buf;      /* raw ep2 DLI bytes                 */
  gsize         capture_len;
  GSList       *rows;             /* captured descrambled lines (g_malloc) */
  gint          lines_recorded;
  gboolean      deactivating;
  gboolean      loop_running;
};
G_DECLARE_FINAL_TYPE (FpDeviceVfs495, fpi_device_vfs495, FPI, DEVICE_VFS495,
                      FpImageDevice)
G_DEFINE_TYPE (FpDeviceVfs495, fpi_device_vfs495, FP_TYPE_IMAGE_DEVICE)

#include "vfs495_descramble.inc"

/* ---------------------------------------------------------------------------
 * DLI line decode (UnpackLineRT): input = one framed line (8-byte header +
 * payload); output = VFS495_LINE_WIDTH descrambled 8-bit pixels.
 * Returns TRUE on success. Only the 8-bit-direct mode (our sensor) is wired up;
 * 4-bit / bit-packed modes are stubbed for other Falcon variants.
 * ------------------------------------------------------------------------- */
static gboolean
vfs495_decode_line (const guint8 *line, gsize len, guint8 *out /* [LINE_WIDTH] */)
{
  guint mode;

  if (len < VFS495_LINE_HDR + VFS495_LINE_WIDTH)
    return FALSE;

  mode = line[6] & 0x0f;
  if (mode != VFS495_DECODE_8BIT)
    {
      /* TODO: 4-bit and variable-bitlength modes (see UnpackLineRT). */
      fp_dbg ("vfs495: unsupported decode mode %u", mode);
      return FALSE;
    }

  /* 8-bit direct: out[descramble[i]] = payload[i] */
  const guint8 *px = line + VFS495_LINE_HDR;
  for (guint i = 0; i < VFS495_LINE_WIDTH; i++)
    out[vfs495_descramble[i]] = px[i];

  return TRUE;
}

/* Assembly pulls the usable main-image columns (0..IMAGE_WIDTH-1). */
static unsigned char
vfs495_get_pixel (struct fpi_line_asmbl_ctx *ctx, GSList *row, unsigned x)
{
  (void) ctx;
  return ((const guint8 *) row->data)[x];
}

static int
vfs495_get_deviation (struct fpi_line_asmbl_ctx *ctx, GSList *a, GSList *b)
{
  /* Mean absolute difference between two lines -> movement proxy. */
  const guint8 *pa = a->data, *pb = b->data;
  int sum = 0;

  for (unsigned x = 0; x < ctx->line_width; x++)
    sum += abs ((int) pa[x] - (int) pb[x]);
  return sum / (int) ctx->line_width;
}

static struct fpi_line_asmbl_ctx assembling_ctx = {
  .line_width         = VFS495_IMAGE_WIDTH,
  .max_height         = 2000,
  .resolution         = 10,
  .median_filter_size = 25,
  .max_search_offset  = 30,
  .get_deviation      = vfs495_get_deviation,
  .get_pixel          = vfs495_get_pixel,
};

/* ---------------------------------------------------------------------------
 * Capture SSM
 * ------------------------------------------------------------------------- */
enum activate_states {
  ACTIVATE_UPLOAD_PATCH,   /* cmd 0x06 x2 (getprint + security patches)      */
  ACTIVATE_OPEN_SESSION,   /* SSLv3 handshake over cmd tunnel (0x11)         */
  ACTIVATE_AWAIT_FINGER,   /* poll finger state / interrupt ep 0x83          */
  ACTIVATE_CAPTURE,        /* read DLI stream from ep 0x82                   */
  ACTIVATE_PROCESS,        /* decode + descramble + assemble                 */
  ACTIVATE_NUM_STATES,
};

static void
vfs495_submit_image (FpiSsm *ssm, FpDeviceVfs495 *self, FpImageDevice *dev)
{
  FpImage *img;

  if (self->lines_recorded < VFS495_IMAGE_WIDTH)
    {
      fpi_image_device_retry_scan (dev, FP_DEVICE_RETRY_TOO_SHORT);
      return;
    }

  self->rows = g_slist_reverse (self->rows);
  img = fpi_assemble_lines (&assembling_ctx, self->rows, self->lines_recorded);
  g_slist_free_full (g_steal_pointer (&self->rows), g_free);
  self->lines_recorded = 0;

  fpi_image_device_image_captured (dev, img);
}

/*
 * Split the raw ep2 DLI buffer into lines, decode+descramble each, and keep the
 * usable main-image columns. NOTE: line framing here is the simple magic-scan
 * placeholder; port irDliRTFalconData's stateful accumulator for robustness
 * (ridge data legitimately contains the 0x01/0xfe marker bytes).
 */
static void
vfs495_process_capture (FpDeviceVfs495 *self)
{
  const guint8 *b = self->capture_buf;
  gsize n = self->capture_len, i = 0;
  guint8 dec[VFS495_LINE_WIDTH];

  while (i + VFS495_LINE_HDR + VFS495_LINE_WIDTH <= n)
    {
      if (b[i] == 0x01 && (b[i + 1] == 0x01 || b[i + 1] == 0xfe) &&
          b[i + 3] == 0x00 && b[i + 7] == 0x00 &&
          vfs495_decode_line (b + i, n - i, dec))
        {
          guint8 *keep = g_malloc (VFS495_IMAGE_WIDTH);
          memcpy (keep, dec, VFS495_IMAGE_WIDTH); /* main-image columns */
          self->rows = g_slist_prepend (self->rows, keep);
          self->lines_recorded++;
          i += VFS495_LINE_HDR + VFS495_LINE_WIDTH;
        }
      else
        {
          i++;
        }
    }
}

static void
activate_run_state (FpiSsm *ssm, FpDevice *_dev)
{
  FpImageDevice *dev = FP_IMAGE_DEVICE (_dev);
  FpDeviceVfs495 *self = FPI_DEVICE_VFS495 (_dev);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case ACTIVATE_UPLOAD_PATCH:
      /* Sensor unlock, step 1: load the firmware "patches" into sensor RAM.
       * Sequence (from BEST-swipe-getprintwait.usb.log, all plaintext, pre-SSL):
       *   GetVersion(01), GetStartInfo(19), DownloadPatch(06, getprint patch),
       *   GetVersion(01), SPI flash id read(1f), SPI flash read(1f),
       *   DownloadPatch(06, security-mgmt patch), GetVersion(01).
       * Each DownloadPatch is [0x06][patch bytes]; sensor replies u16 status 0.
       * The patch blobs are HP's proprietary firmware -- NOT embedded here.
       * vfs495_load_patches() must read them from HP's SoftPaq (sp84530,
       * HPUsbVFS495 image / captured blobs) supplied by the user at runtime.
       * See vfs495_proto.h and driver/README.md. */
      /* TODO: implement vfs495_send(dev, {0x01}); ... ; vfs495_send_patch(dev, blob, len);
       * using fpi_usb_transfer on EP_CMD_OUT/IN. */
      fpi_image_device_activate_complete (dev, NULL);
      fpi_ssm_next_state (ssm);
      break;

    case ACTIVATE_OPEN_SESSION:
      /* Sensor unlock, step 2: the mandatory SSLv3 session (capture cmd 0x02 is
       * refused 0x0404 without it -- verified). Fully specified in
       * driver/SSL_PROTOCOL.md: ClientHello (suites 0044/0043/0042) -> ServerHello,
       * fetch sensor RSA-2048 pubkey via scsGetDataFromStorage(id 10), RSA-encrypt
       * a 48-byte premaster -> ClientKeyExchange, SSLv3 MD5/SHA1 master + key block
       * -> AES-256-CBC keys, CCS + Finished. AppData (17 03 00 ...) wraps the VCSFW
       * capture command; the image itself stays plaintext on EP_DATA_IN.
       * TODO: implement in vfs495_ssl.c using NSS (RSA/MD5/SHA1/AES) which libfprint
       * already links. Reference vectors: captures/ssl_secrets.json. */
      fpi_ssm_next_state (ssm);
      break;

    case ACTIVATE_AWAIT_FINGER:
      /* TODO: wait on interrupt ep 0x83 (finger event) or poll GET_FINGER_STATE. */
      fpi_ssm_next_state (ssm);
      break;

    case ACTIVATE_CAPTURE:
      /* TODO: issue GET_FINGERPRINT and read the DLI stream from ep 0x82 into
       * self->capture_buf / capture_len via fpi_usb_transfer. */
      fpi_ssm_next_state (ssm);
      break;

    case ACTIVATE_PROCESS:
      if (self->capture_buf && self->capture_len)
        vfs495_process_capture (self);
      vfs495_submit_image (ssm, self, dev);
      fpi_ssm_mark_completed (ssm);
      break;
    }
}

static void
activate_complete (FpiSsm *ssm, FpDevice *_dev, GError *error)
{
  FpImageDevice *dev = FP_IMAGE_DEVICE (_dev);
  FpDeviceVfs495 *self = FPI_DEVICE_VFS495 (_dev);

  self->loop_running = FALSE;
  g_clear_pointer (&self->capture_buf, g_free);
  self->capture_len = 0;

  if (self->deactivating)
    fpi_image_device_deactivate_complete (dev, error);
  else if (error)
    fpi_image_device_session_error (dev, error);
}

/* ---------------------------------------------------------------------------
 * Device lifecycle
 * ------------------------------------------------------------------------- */
static void
dev_open (FpImageDevice *dev)
{
  GError *error = NULL;
  GUsbDevice *usb = fpi_device_get_usb_device (FP_DEVICE (dev));

  if (!g_usb_device_claim_interface (usb, 0, 0, &error))
    {
      fpi_image_device_open_complete (dev, error);
      return;
    }
  fpi_image_device_open_complete (dev, NULL);
}

static void
dev_close (FpImageDevice *dev)
{
  GError *error = NULL;
  FpDeviceVfs495 *self = FPI_DEVICE_VFS495 (dev);

  g_clear_pointer (&self->capture_buf, g_free);
  g_slist_free_full (g_steal_pointer (&self->rows), g_free);
  g_usb_device_release_interface (fpi_device_get_usb_device (FP_DEVICE (dev)),
                                  0, 0, &error);
  fpi_image_device_close_complete (dev, error);
}

static void
dev_activate (FpImageDevice *dev)
{
  FpDeviceVfs495 *self = FPI_DEVICE_VFS495 (dev);
  FpiSsm *ssm;

  self->deactivating = FALSE;
  self->loop_running = TRUE;
  ssm = fpi_ssm_new (FP_DEVICE (dev), activate_run_state, ACTIVATE_NUM_STATES);
  fpi_ssm_start (ssm, activate_complete);
}

static void
dev_deactivate (FpImageDevice *dev)
{
  FpDeviceVfs495 *self = FPI_DEVICE_VFS495 (dev);

  if (self->loop_running)
    self->deactivating = TRUE;
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

  img_class->bz3_threshold = 20;
  img_class->img_width = VFS495_IMAGE_WIDTH;
  img_class->img_height = -1;
}
