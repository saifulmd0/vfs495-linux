#!/usr/bin/env python3
"""VFS495 swipe assembly modelled on HP's IRreconstructImage chain (see docs/FINDINGS.md).

    descrambled lines (n, 264) -> finger span -> start at sustained contact + motion -> drop resting lines
    -> aux->main lag per line (Viterbi-smoothed) -> 7/lag output rows per line, linear interpolation between lines, max 300 rows
    -> raw sensor values, column percentile stretch, inverted, mirrored  -> uint8, 200 wide

Validated offline against HP's own images of the same swipes (6 swipes, vfs495-match scores):
HP vs HP 77.7, this vs HP 50.5 (18/30 >= 40), this vs this 48.8; the old reconstruct.py path 2.5 / 15.7.
Live (native capture, 6 swipes incl. 2 resting first): one-to-one mean 39.4, 7/15 >= 40.
Phase 6 (driver, 10 swipes finger A + 5 finger B): the sustained-contact start and REF_LAG 7 took genuine
pairs from mean 22.4 (12/55 >= 40) to 47.6 (29/55); impostor pairs max 14 (0/50 >= 40). driver/PLAN.md.
"""
import numpy as np
from scipy.ndimage import gaussian_filter, gaussian_filter1d

MAIN = 200            # print columns
AUX0, AUXW = 200, 64  # second sensor row: frame columns 200..263
X0 = 70               # main column under aux column 0
REF_LAG = 7.0         # lag of 7 lines = 1 output row. HP uses 8 (best against HP's images); 7 is best for
                      # matching our own swipes (more of the finger fits in 300 rows; 6 and 8 score lower)
MAX_ROWS = 300        # HP stops filling at 300 rows
LAGS = np.arange(20, 252, 2)   # plausible aux->main lags in lines (real swipes: ~50..170)


def _zn(a):
    a = a - a.mean(1, keepdims=True)
    return a / (np.linalg.norm(a, axis=1, keepdims=True) + 1e-6)


def prep(lines):
    """Ridge band only, for motion estimation (not used for the output pixels)."""
    res = lines.astype(np.float32)
    res = res - res.mean(0, keepdims=True)                  # fixed column pattern
    return res - gaussian_filter(res, sigma=(0, 4))


def contact_energy(res, frac=0.3):
    """Smoothed ridge energy per line and the full-contact threshold median + frac*(max-median)."""
    bp = gaussian_filter(res[:, :MAIN], (3, 1)) - gaussian_filter(res[:, :MAIN], (24, 6))
    e = gaussian_filter1d((bp ** 2).mean(1), 25)
    return e, np.median(e) + frac * (e.max() - np.median(e))


def finger_span(res, endfrac=0.1, pad=20):
    """Contact = energy first above the contact threshold; end = last line above endfrac*max.
    The tail of a swipe has low contrast but HP still uses it, so the end threshold is low."""
    e, thr = contact_energy(res)
    on = np.where(e > thr)[0]
    if not len(on):
        return 0, len(res)
    tail = np.where(e > endfrac * e.max())[0]
    return max(0, on[0] - pad), min(len(res), max(on[-1], tail[-1]) + pad)


def moving(res, k=64, still=0.75):
    """False where the finger rests (HP's detectStictionZone): a line then still looks like the line
    k lines earlier (similarity ~0.85-0.95), while a moving finger drops it below ~0.5 within k lines."""
    m = _zn(res[:, :MAIN])
    sim = np.ones(len(m))
    sim[k:] = (m[k:] * m[:-k]).sum(1)
    return gaussian_filter1d(sim, 10) < still


def swipe_start(res, mv, sustain=150):
    """First line where the finger both moves and is in full contact, for most (80 %) of the next
    `sustain` lines (HP: detectNoiseBeforeBase). Before it: touch-down spike, then a settling finger
    whose noisy, weak-contact lines look like motion and assembled into smears. None if never."""
    e, thr = contact_energy(res)
    cond = (mv & (e > thr)).astype(int)
    cond = np.convolve(cond, np.ones(sustain, int), "full")[sustain - 1:] * 5 >= sustain * 4   # >= 80 %
    first = np.where(cond)[0]
    return int(first[0]) if len(first) else None


def lag_curve(res, step=16, win=48, xs=range(-8, 9, 2), penalty=0.01, mv=None):
    """Per-line lag between the aux row and main columns X0..X0+63 (finger speed = 4.3 px / lag).
    Windowed correlation for every (window, lag), then the best path with a cost per unit of lag
    change: a smooth curve, like HP's gap interpolation + median + stable-segment cleanup.
    A constant lag per swipe (infinite penalty) scores far worse: the speed does change mid-swipe."""
    n = len(res)
    aux = _zn(res[:, AUX0:AUX0 + AUXW])
    k = np.ones(win) / win
    centres = np.arange(win // 2, max(win // 2 + 1, n - win // 2), step)
    S = np.full((len(centres), len(LAGS)), -1.0)
    for dx in xs:
        m = _zn(res[:, X0 + dx:X0 + dx + AUXW])
        for j, L in enumerate(LAGS):
            p = np.full(n, -1.0)
            if L < n:
                p[:n - L] = (aux[:n - L] * m[L:]).sum(1)
            S[:, j] = np.maximum(S[:, j], np.convolve(p, k, "same")[centres])
    if mv is not None:                                      # resting finger: no lag information
        S[np.convolve(mv, k, "same")[centres] < 0.5] = 0.0
    cost = penalty * np.abs(LAGS[:, None] - LAGS[None, :])
    D = S[0].copy()
    back = np.zeros(S.shape, int)
    for t in range(1, len(S)):
        M = D[None, :] - cost                               # [to, from]
        back[t] = M.argmax(1)
        D = M.max(1) + S[t]
    path = [int(D.argmax())]
    for t in range(len(S) - 1, 0, -1):
        path.append(back[t, path[-1]])
    return np.interp(np.arange(n), centres, LAGS[path[::-1]].astype(float))


def emit_rows(main, lag, mv=None, ref=REF_LAG, max_rows=MAX_ROWS):
    """Each moving input line advances the output by ref/lag rows (resting lines by 0); every output
    row is a linear blend of the two input lines around it (HP's IRinterpolateLine)."""
    v = ref / np.maximum(lag, 1.0)
    if mv is not None:
        v = v * mv
    pos = np.concatenate([[0.0], np.cumsum(v)[:-1]])
    rows = min(int(pos[-1]), max_rows)
    if rows < 2:
        return main[:2]
    keep = np.concatenate([[True], np.diff(pos) > 0])      # interp needs increasing positions
    f = np.interp(np.arange(rows, dtype=float), pos[keep], np.arange(len(main))[keep])
    lo = np.floor(f).astype(int)
    hi = np.minimum(lo + 1, len(main) - 1)
    w = (f - lo)[:, None]
    return main[lo] * (1 - w) + main[hi] * w


def contrast_cols(img, lo=1, hi=94):
    """HP's column contrast stretch (IRConstrastEnhanceImageCols percentiles)."""
    a = np.percentile(img, lo, axis=0)
    b = np.percentile(img, hi, axis=0)
    return np.clip((img - a) / np.maximum(b - a, 1e-6), 0, 1)


def swipe_stats(lag, mv):
    """Speed and length of the swipe (driver/vfs495_assemble.c swipe_stats, the TOO_FAST gate)."""
    m = lag[mv]
    return {"moving": int(mv.sum()),
            "median_lag": float(np.percentile(m, 50)) if len(m) else 0.0,
            "floor_frac": float((m <= LAGS[0] + 1).mean()) if len(m) else 0.0,
            "rows": float(np.sum((REF_LAG / np.maximum(lag, 1.0) * mv)[:-1]))}


def assemble(lines, stats=None):
    """lines: (n, 264) descrambled scan lines. Returns a uint8 image (<= 300 x 200) like HP's.
    stats (a dict, optional) receives swipe_stats()."""
    res = prep(lines)
    lo, hi = finger_span(res)
    mv = moving(res)
    start = swipe_start(res, mv)
    if start is not None and lo <= start < hi:
        lo = start
    on = np.where(mv[lo:hi])[0]
    if len(on):                                             # start at the first moving line, not at contact
        lo, hi = lo + on[0], lo + on[-1] + 1
    mv = mv[lo:hi]
    lag = lag_curve(res[lo:hi], mv=mv)
    if stats is not None:
        stats.update(swipe_stats(lag, mv))
    img = emit_rows(lines[lo:hi, :MAIN].astype(np.float32), lag, mv)   # raw values: keep pores/ridge shape
    img = 1 - contrast_cols(img)                            # HP's polarity is inverted vs raw
    return (img[:, ::-1] * 255).astype(np.uint8)            # and L-R mirrored
