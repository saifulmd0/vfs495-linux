/*
 * Validity VFS495 (138a:003f) fingerprint reader driver for libfprint
 * Protocol constants reverse-engineered from HP's Validity 4.5-136 Linux driver.
 * See vfs495-re/NOTES.md for the full derivation.
 */
#pragma once

/* USB */
#define VFS495_VID 0x138a
#define VFS495_PID 0x003f
#define VFS495_EP_CMD_OUT 0x01     /* bulk OUT: commands            */
#define VFS495_EP_CMD_IN  0x81     /* bulk IN:  command replies     */
#define VFS495_EP_DATA_IN 0x82     /* bulk IN:  image (DLI) stream  */
#define VFS495_EP_IRQ_IN  0x83     /* interrupt IN: finger events   */

/* VCSFW command IDs (first payload byte). Reply begins with a u16 status. */
enum vfs495_cmd {
  VFS495_CMD_GET_VERSION       = 0x01,
  VFS495_CMD_GET_CONFIGURATION = 0x15, /* also GetFingerprint family */
  VFS495_CMD_ABORT             = 0x04,
  VFS495_CMD_RESET             = 0x05,
  VFS495_CMD_DOWNLOAD_PATCH    = 0x06, /* [0x06][patch bytes]        */
  VFS495_CMD_PEEK              = 0x07,
  VFS495_CMD_POKE              = 0x08,
  VFS495_CMD_GPIO              = 0x0d,
  VFS495_CMD_GET_FINGERPRINT   = 0x15,
  VFS495_CMD_GET_FINGER_STATE  = 0x17,
  VFS495_CMD_GET_START_INFO    = 0x19,
  VFS495_CMD_UNLOAD_PATCH      = 0x1a,
  VFS495_CMD_SPI_BULK_READ     = 0x1f,
};

/*
 * Image geometry (from UnpackLineRT config, width = cfg[1] = 264).
 * The 264-wide descrambled line is: cols 0..199 main image, cols 200..263 a
 * low-res auxiliary/tracking sub-image. Assembly uses the main 200 columns.
 */
#define VFS495_LINE_WIDTH   264   /* descrambled pixels per line   */
#define VFS495_IMAGE_WIDTH  200   /* usable main-image columns     */
#define VFS495_LINE_HDR     8     /* per-line header, skipped      */

/*
 * DLI line framing (irDliRTFalconData): lines are delimited in the ep2 stream by
 * a 0x01 byte whose following byte is 0x01 or 0xfe; each line = 8-byte header +
 * payload. Decode mode = header[6] & 0x0f: 8 = direct 8-bit (one byte/pixel,
 * our sensor), 4 = 4-bit packed, else = variable-bitlength packed. Output pixels
 * are scattered through the descramble table (see vfs495_descramble.inc).
 */
#define VFS495_DECODE_8BIT 8
#define VFS495_DECODE_4BIT 4
