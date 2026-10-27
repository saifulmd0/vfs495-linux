/*
 * Validity VFS495: swipe assembly. See vfs495_assemble.h; every function mirrors the one of the same
 * name in tools/vfs495_assemble.py (scipy/numpy semantics reproduced: gaussian_filter with
 * truncate 4 and 'reflect' borders, np.convolve 'same', np.interp, np.percentile 'linear').
 *
 * This library is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License, version 2.1 or later.
 */

#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "vfs495_assemble.h"

#define W        264          /* descrambled line */
#define MAIN     VFS495_ASM_WIDTH
#define AUX0     200          /* second sensor row: columns 200..263 */
#define AUXW     64
#define X0       70           /* main column under aux column 0 */
#define REF_LAG  7.0          /* a lag of 7 lines = 1 output row (HP: 8; 7 matches best, PLAN.md phase 6) */
#define SUSTAIN  150          /* swipe start: moving + full contact for >= 80 % of the next 150 lines */
#define LAG_MIN  VFS495_ASM_LAG_MIN   /* plausible aux->main lags: 20, 22, .. 250 lines */
#define LAG_STEP 2
#define NLAGS    116
#define STEP     16           /* lag window spacing */
#define WIN      48           /* lag window length */
#define PENALTY  0.01         /* Viterbi cost per line of lag change */

/* ---- numpy / scipy building blocks ----------------------------------------- */

/* scipy.ndimage 'reflect': d c b a | a b c d | d c b a */
static gsize
reflect (gssize i, gsize n)
{
  gssize period = 2 * (gssize) n;

  i %= period;
  if (i < 0)
    i += period;
  return i < (gssize) n ? (gsize) i : (gsize) (period - 1 - i);
}

static void gauss_rows (float *a, gsize rows, gsize cols, int axis, double sigma);

/* gaussian_filter1d along one axis of a rows x cols float array, in place */
static void
gauss_axis (float *a, gsize rows, gsize cols, int axis, double sigma)
{
  g_autofree float *t = NULL;

  if (axis == 1 || sigma <= 0)
    {
      gauss_rows (a, rows, cols, axis, sigma);
      return;
    }
  t = g_new (float, rows * cols);                 /* transpose, filter along rows, transpose back */
  for (gsize r = 0; r < rows; r++)
    for (gsize c = 0; c < cols; c++)
      t[c * rows + r] = a[r * cols + c];
  gauss_rows (t, cols, rows, 1, sigma);
  for (gsize r = 0; r < rows; r++)
    for (gsize c = 0; c < cols; c++)
      a[r * cols + c] = t[c * rows + r];
}

static void
gauss_rows (float *a, gsize rows, gsize cols, int axis, double sigma)
{
  int radius = (int) (4.0 * sigma + 0.5);
  gsize len = axis == 0 ? rows : cols, count = axis == 0 ? cols : rows;
  gsize stride = axis == 0 ? cols : 1, step = axis == 0 ? 1 : cols;
  g_autofree double *k = g_new (double, 2 * radius + 1);
  g_autofree double *line = g_new (double, len);
  double sum = 0;

  if (sigma <= 0)
    return;
  for (int i = -radius; i <= radius; i++)
    sum += k[i + radius] = exp (-0.5 * i * i / (sigma * sigma));
  for (int i = 0; i <= 2 * radius; i++)
    k[i] /= sum;

  for (gsize c = 0; c < count; c++)
    {
      float *p = a + c * step;

      for (gsize i = 0; i < len; i++)
        line[i] = p[i * stride];
      for (gsize i = 0; i < len; i++)
        {
          double acc = 0;

          if (i >= (gsize) radius && i + radius < len)
            {
              const double *l = line + i - radius;

              for (int j = 0; j <= 2 * radius; j++)
                acc += k[j] * l[j];
            }
          else
            for (int j = -radius; j <= radius; j++)
              acc += k[j + radius] * line[reflect ((gssize) i + j, len)];
          p[i * stride] = (float) acc;
        }
    }
}

/* gaussian_filter1d of a float64 vector (scipy keeps float64 here) */
static void
gauss1d (double *v, gsize n, double sigma)
{
  int radius = (int) (4.0 * sigma + 0.5);
  g_autofree double *k = g_new (double, 2 * radius + 1);
  g_autofree double *src = g_memdup2 (v, n * sizeof (double));
  double sum = 0;

  for (int i = -radius; i <= radius; i++)
    sum += k[i + radius] = exp (-0.5 * i * i / (sigma * sigma));
  for (int i = 0; i <= 2 * radius; i++)
    k[i] /= sum;
  for (gsize i = 0; i < n; i++)
    {
      double acc = 0;

      for (int j = -radius; j <= radius; j++)
        acc += k[j + radius] * src[reflect ((gssize) i + j, n)];
      v[i] = acc;
    }
}

static int
cmp_double (const void *a, const void *b)
{
  double x = *(const double *) a, y = *(const double *) b;

  return (x > y) - (x < y);
}

/* np.percentile, linear interpolation; sorts v */
static double
percentile (double *v, gsize n, double q)
{
  double idx = q / 100.0 * (n - 1);
  gsize lo = (gsize) floor (idx), hi = MIN (lo + 1, n - 1);

  qsort (v, n, sizeof (double), cmp_double);
  return v[lo] + (v[hi] - v[lo]) * (idx - lo);
}

/* np.interp(x, xp, fp) for increasing xp, clamped at the ends */
static double
interp (double x, const double *xp, const double *fp, gsize n)
{
  gsize lo = 0, hi = n - 1;

  if (x <= xp[0])
    return fp[0];
  if (x >= xp[n - 1])
    return fp[n - 1];
  while (hi - lo > 1)
    {
      gsize mid = (lo + hi) / 2;

      if (xp[mid] <= x)
        lo = mid;
      else
        hi = mid;
    }
  return fp[lo] + (fp[hi] - fp[lo]) * (x - xp[lo]) / (xp[hi] - xp[lo]);
}

/* rows of a - row mean, scaled to unit norm (+1e-6), for columns c0 .. c0+len-1 */
static float *
zn (const float *res, gsize n, gsize c0, gsize len)
{
  float *out = g_new (float, n * len);

  for (gsize t = 0; t < n; t++)
    {
      const float *r = res + t * W + c0;
      float *o = out + t * len;
      double mean = 0, norm = 0;

      for (gsize x = 0; x < len; x++)
        mean += r[x];
      mean /= len;
      for (gsize x = 0; x < len; x++)
        {
          o[x] = r[x] - mean;
          norm += (double) o[x] * o[x];
        }
      norm = sqrt (norm) + 1e-6;
      for (gsize x = 0; x < len; x++)
        o[x] /= norm;
    }
  return out;
}

static double
dot (const float *a, const float *b, gsize len)
{
  float s = 0;

  for (gsize x = 0; x < len; x++)
    s += a[x] * b[x];
  return s;
}

/* ---- the pipeline ---------------------------------------------------------- */

/* Ridge band only, for motion estimation. */
static float *
prep (const guint8 *lines, gsize n)
{
  float *res = g_new (float, n * W);
  g_autofree float *smooth = NULL;

  for (gsize x = 0; x < W; x++)
    {
      double mean = 0;

      for (gsize t = 0; t < n; t++)
        mean += lines[t * W + x];
      mean /= n;
      for (gsize t = 0; t < n; t++)
        res[t * W + x] = lines[t * W + x] - (float) mean;   /* fixed column pattern */
    }
  smooth = g_memdup2 (res, n * W * sizeof (float));
  gauss_axis (smooth, n, W, 1, 4);
  for (gsize i = 0; i < n * W; i++)
    res[i] -= smooth[i];
  return res;
}

/* finger_span + swipe_start share the smoothed ridge energy e and the contact threshold */
static void
finger_span (const float *res, gsize n, gsize *lo, gsize *hi, double **energy, double *contact)
{
  g_autofree float *a = g_new (float, n * MAIN);
  g_autofree float *b = NULL;
  g_autofree double *e = g_new (double, n);
  g_autofree double *sorted = NULL;
  double med, emax = 0, thr;
  gssize first = -1, last = -1, tail = -1;

  for (gsize t = 0; t < n; t++)
    memcpy (a + t * MAIN, res + t * W, MAIN * sizeof (float));
  b = g_memdup2 (a, n * MAIN * sizeof (float));
  gauss_axis (a, n, MAIN, 0, 3);
  gauss_axis (a, n, MAIN, 1, 1);
  gauss_axis (b, n, MAIN, 0, 24);
  gauss_axis (b, n, MAIN, 1, 6);
  for (gsize t = 0; t < n; t++)
    {
      double s = 0;

      for (gsize x = 0; x < MAIN; x++)
        {
          float d = a[t * MAIN + x] - b[t * MAIN + x];
          s += (double) d * d;
        }
      e[t] = s / MAIN;
    }
  gauss1d (e, n, 25);

  sorted = g_memdup2 (e, n * sizeof (double));
  qsort (sorted, n, sizeof (double), cmp_double);
  med = n % 2 ? sorted[n / 2] : (sorted[n / 2 - 1] + sorted[n / 2]) / 2;
  for (gsize t = 0; t < n; t++)
    emax = MAX (emax, e[t]);
  thr = med + 0.3 * (emax - med);
  *contact = thr;
  for (gsize t = 0; t < n; t++)
    {
      if (e[t] > thr)
        {
          if (first < 0)
            first = t;
          last = t;
        }
      if (e[t] > 0.1 * emax)
        tail = t;
    }
  *energy = g_steal_pointer (&e);
  if (first < 0)
    {
      *lo = 0;
      *hi = n;
      return;
    }
  *lo = first >= 20 ? first - 20 : 0;
  *hi = MIN (n, (gsize) MAX (last, tail) + 20);
}

/* First line where the finger both moves and is in full contact for >= 80 % of the next SUSTAIN lines
 * (HP: detectNoiseBeforeBase). Before it: the touch-down spike, then a settling finger whose noisy
 * weak-contact lines look like motion. Returns -1 if there is none. */
static gssize
swipe_start (const double *e, double thr, const gboolean *mv, gsize n)
{
  g_autofree guint *prefix = g_new (guint, n + 1);

  prefix[0] = 0;
  for (gsize t = 0; t < n; t++)
    prefix[t + 1] = prefix[t] + (mv[t] && e[t] > thr);
  for (gsize t = 0; t < n; t++)
    if ((prefix[MIN (t + SUSTAIN, n)] - prefix[t]) * 5 >= SUSTAIN * 4)
      return t;
  return -1;
}

/* FALSE where the finger rests (HP's detectStictionZone). */
static gboolean *
moving (const float *res, gsize n)
{
  const gsize k = 64;
  g_autofree float *m = zn (res, n, 0, MAIN);
  g_autofree double *sim = g_new (double, n);
  gboolean *mv = g_new (gboolean, n);

  for (gsize t = 0; t < n; t++)
    sim[t] = t < k ? 1.0 : dot (m + t * MAIN, m + (t - k) * MAIN, MAIN);
  gauss1d (sim, n, 10);
  for (gsize t = 0; t < n; t++)
    mv[t] = sim[t] < 0.75;
  return mv;
}

/* np.convolve(p, ones(WIN)/WIN, 'same')[c]: the mean of p[c-24 .. c+23] (zeros outside) */
static double
window_mean (const double *prefix, gsize n, gsize c)
{
  gssize a = (gssize) c - WIN / 2, b = (gssize) c + WIN / 2 - 1;

  a = MAX (a, 0);
  b = MIN (b, (gssize) n - 1);
  return (prefix[b + 1] - prefix[a]) / WIN;
}

/* Per-line aux->main lag: windowed correlation for every (window, lag), then the best path with a
 * cost per unit of lag change. Windows where the finger mostly rests carry no lag information. */
static double *
lag_curve (const float *res, gsize n, const gboolean *mv)
{
  g_autofree float *aux = zn (res, n, AUX0, AUXW);
  g_autofree double *prefix = g_new (double, n + 1);
  g_autofree double *p = g_new (double, n);
  g_autofree gsize *centres = NULL;
  g_autofree double *S = NULL, *D = NULL, *M = NULL;
  g_autofree int *back = NULL, *path = NULL;
  g_autofree double *xc = NULL, *lc = NULL;
  gsize T = 0;
  double *lag = g_new (double, n);

  for (gsize c = WIN / 2; c < MAX (WIN / 2 + 1, n - MIN (n, WIN / 2)); c += STEP)
    T++;
  centres = g_new (gsize, T);
  for (gsize i = 0; i < T; i++)
    centres[i] = WIN / 2 + i * STEP;
  S = g_new (double, T * NLAGS);
  for (gsize i = 0; i < T * NLAGS; i++)
    S[i] = -1.0;

  for (int dx = -8; dx <= 8; dx += 2)
    {
      g_autofree float *m = zn (res, n, X0 + dx, AUXW);

      for (int j = 0; j < NLAGS; j++)
        {
          gsize L = LAG_MIN + LAG_STEP * j;

          for (gsize t = 0; t < n; t++)
            p[t] = t + L < n ? dot (aux + t * AUXW, m + (t + L) * AUXW, AUXW) : -1.0;
          prefix[0] = 0;
          for (gsize t = 0; t < n; t++)
            prefix[t + 1] = prefix[t] + p[t];
          for (gsize i = 0; i < T; i++)
            S[i * NLAGS + j] = MAX (S[i * NLAGS + j], window_mean (prefix, n, centres[i]));
        }
    }

  prefix[0] = 0;
  for (gsize t = 0; t < n; t++)
    prefix[t + 1] = prefix[t] + (mv[t] ? 1.0 : 0.0);
  for (gsize i = 0; i < T; i++)
    if (window_mean (prefix, n, centres[i]) < 0.5)
      for (int j = 0; j < NLAGS; j++)
        S[i * NLAGS + j] = 0.0;

  /* Viterbi; ties go to the lowest index, like numpy argmax */
  D = g_memdup2 (S, NLAGS * sizeof (double));
  M = g_new (double, NLAGS);
  back = g_new0 (int, T * NLAGS);
  for (gsize t = 1; t < T; t++)
    {
      for (int to = 0; to < NLAGS; to++)
        {
          double best = -G_MAXDOUBLE;
          int arg = 0;

          for (int from = 0; from < NLAGS; from++)
            {
              double v = D[from] - PENALTY * LAG_STEP * abs (to - from);
              if (v > best)
                {
                  best = v;
                  arg = from;
                }
            }
          M[to] = best + S[t * NLAGS + to];
          back[t * NLAGS + to] = arg;
        }
      memcpy (D, M, NLAGS * sizeof (double));
    }
  path = g_new (int, T);
  path[T - 1] = 0;
  for (int j = 1; j < NLAGS; j++)
    if (D[j] > D[path[T - 1]])
      path[T - 1] = j;
  for (gsize t = T - 1; t > 0; t--)
    path[t - 1] = back[t * NLAGS + path[t]];

  xc = g_new (double, T);
  lc = g_new (double, T);
  for (gsize i = 0; i < T; i++)
    {
      xc[i] = centres[i];
      lc[i] = LAG_MIN + LAG_STEP * path[i];
    }
  for (gsize t = 0; t < n; t++)
    lag[t] = interp (t, xc, lc, T);
  return lag;
}

/* swipe_stats: speed and length of the swipe, for the driver's TOO_FAST / TOO_SHORT decision */
static void
swipe_stats (const double *lag, const gboolean *mv, gsize n, double rows, Vfs495AsmStats *stats)
{
  g_autofree double *v = g_new (double, n);
  gsize m = 0, at_floor = 0;

  for (gsize t = 0; t < n; t++)
    if (mv[t])
      {
        v[m++] = lag[t];
        at_floor += lag[t] <= LAG_MIN + LAG_STEP / 2.0;
      }
  stats->moving = m;
  stats->median_lag = m ? percentile (v, m, 50) : 0;
  stats->floor_frac = m ? (double) at_floor / m : 0;
  stats->rows = rows;
}

guint8 *
vfs495_assemble (const guint8 *lines, gsize n_all, guint *height, Vfs495AsmStats *stats)
{
  Vfs495AsmStats dummy;
  g_autofree float *res = NULL;
  g_autofree gboolean *mv_all = NULL;
  g_autofree double *energy = NULL;
  double contact = 0;
  gssize start;
  g_autofree double *lag = NULL, *pos = NULL, *xp = NULL, *fp = NULL, *col = NULL, *img = NULL;
  gsize lo, hi, n, rows, nk = 0;
  guint8 *out;

  if (!stats)
    stats = &dummy;
  memset (stats, 0, sizeof (*stats));
  if (n_all < 2 * WIN)
    return NULL;
  res = prep (lines, n_all);
  finger_span (res, n_all, &lo, &hi, &energy, &contact);
  mv_all = moving (res, n_all);
  start = swipe_start (energy, contact, mv_all, n_all);
  if (start >= (gssize) lo && start < (gssize) hi)
    lo = start;
  {
    gssize first = -1, last = -1;

    for (gsize t = lo; t < hi; t++)
      if (mv_all[t])
        {
          if (first < 0)
            first = t;
          last = t;
        }
    if (first >= 0)                     /* start at the first moving line, not at contact */
      {
        lo = first;
        hi = last + 1;
      }
  }
  n = hi - lo;
  if (n < 2 * WIN)
    return NULL;

  lag = lag_curve (res + lo * W, n, mv_all + lo);

  /* emit_rows: each moving line advances the output by REF_LAG / lag rows */
  pos = g_new (double, n);
  pos[0] = 0;
  for (gsize t = 1; t < n; t++)
    pos[t] = pos[t - 1] + (mv_all[lo + t - 1] ? REF_LAG / MAX (lag[t - 1], 1.0) : 0.0);
  swipe_stats (lag, mv_all + lo, n, pos[n - 1], stats);
  rows = MIN ((gsize) pos[n - 1], VFS495_ASM_MAX_ROWS);
  if (rows < 2)
    return NULL;
  xp = g_new (double, n);
  fp = g_new (double, n);
  for (gsize t = 0; t < n; t++)
    if (t == 0 || pos[t] > pos[t - 1])
      {
        xp[nk] = pos[t];
        fp[nk++] = t;
      }
  img = g_new (double, rows * MAIN);
  for (gsize r = 0; r < rows; r++)
    {
      double f = interp (r, xp, fp, nk), w;
      gsize a = (gsize) floor (f), b = MIN (a + 1, n - 1);

      w = f - a;
      for (gsize x = 0; x < MAIN; x++)
        img[r * MAIN + x] = (float) lines[(lo + a) * W + x] * (1 - w) + (float) lines[(lo + b) * W + x] * w;
    }

  /* contrast_cols (1 / 94 percentiles), inverted polarity, mirrored */
  out = g_new (guint8, rows * MAIN);
  col = g_new (double, rows);
  for (gsize x = 0; x < MAIN; x++)
    {
      double pl, ph;

      for (gsize r = 0; r < rows; r++)
        col[r] = img[r * MAIN + x];
      pl = percentile (col, rows, 1);
      ph = percentile (col, rows, 94);
      for (gsize r = 0; r < rows; r++)
        {
          double v = (img[r * MAIN + x] - pl) / MAX (ph - pl, 1e-6);

          v = 1 - CLAMP (v, 0, 1);
          out[r * MAIN + (MAIN - 1 - x)] = (guint8) (v * 255);
        }
    }
  *height = rows;
  return out;
}
