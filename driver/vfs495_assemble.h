/*
 * Validity VFS495: swipe assembly, a C port of tools/vfs495_assemble.py (modelled on HP's
 * IRreconstructImage; validated against HP's own images, see docs/FINDINGS.md 2026-10-10).
 *
 * descrambled lines -> finger span -> drop resting-finger lines (stiction) -> aux->main lag per line
 * (windowed correlation + Viterbi smoothing) -> 8/lag output rows per line, linear interpolation,
 * max 300 rows -> raw values, column percentile stretch, inverted, mirrored.
 * Pure GLib + libm, testable outside libfprint (tests/test_assemble.sh).
 */
#pragma once

#include <glib.h>

#define VFS495_ASM_WIDTH    200      /* output columns (main sensor row) */
#define VFS495_ASM_MAX_ROWS 300

/* What the assembly saw, for the driver's quality gate (tools/vfs495_assemble.py swipe_stats). */
typedef struct
{
  guint  moving;       /* lines the finger moved in (the part that becomes the print) */
  double median_lag;   /* aux->main lag, lines: finger speed ~ 1 / lag. 0 if no lag curve */
  double floor_frac;   /* fraction of moving lines whose lag is at the search floor (too fast to measure) */
  double rows;         /* print length before the 300-row cap */
} Vfs495AsmStats;

#define VFS495_ASM_LAG_MIN  20   /* the lag search floor, lines */

/* lines: n x 264 descrambled pixels. Returns VFS495_ASM_WIDTH x *height pixels (g_free), or NULL
 * when nothing usable was found. stats (nullable) is filled in either case. */
guint8 *vfs495_assemble (const guint8   *lines,
                         gsize           n,
                         guint          *height,
                         Vfs495AsmStats *stats);
