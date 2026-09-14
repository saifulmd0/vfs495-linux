#!/usr/bin/env python3
"""Reconstruct a VFS495 fingerprint from harvested descrambled scan lines.

Input: lines.raw  = repeated [u16 len][len bytes] records (len=264), the descrambled
scanlines dumped from UnpackLineRT (see runtime/harvest_lines.py).

Pipeline:
  1. stack lines, drop the fixed per-column pattern (sensor gain), bandpass for ridges
  2. motion model: novelty[i] = 1 - corr(line[i], line[i-1]); stationary runs -> ~0
  3. segment into continuous-motion runs; pick the best (longest high-novelty) swipe
  4. resample that run to uniform finger displacement (undo slow-swipe stretch)
  5. contrast-normalize -> output PGM/PNG
"""
import sys

import numpy as np
from scipy.ndimage import gaussian_filter, gaussian_filter1d

W = 264


def load(path):
    d = open(path, "rb").read()
    rows, i = [], 0
    while i + 2 <= len(d):
        n = int.from_bytes(d[i : i + 2], "little")
        i += 2
        if i + n > len(d):
            break
        rows.append(np.frombuffer(d[i : i + n], np.uint8).astype(np.float32))
        i += n
    return np.array(rows)


def preprocess(img):
    res = img - img.mean(0, keepdims=True)          # remove fixed column pattern
    res = res - gaussian_filter(res, sigma=(0, 4))  # high-pass along width (ridge band)
    return res


def novelty(res):
    a, b = res[:-1], res[1:]
    num = (a * b).sum(1)
    den = np.sqrt((a**2).sum(1) * (b**2).sum(1)) + 1e-6
    nov = np.clip(1 - num / den, 0, None)
    return np.concatenate([[0], gaussian_filter1d(nov, 2)])


def finger_energy(res):
    """Per-row ridge energy. High only where a finger is actually on the sensor."""
    return gaussian_filter1d(np.abs(res).mean(1), 10)


def best_segment(energy, bridge=120):
    """Longest finger-present run; bridge short dropouts so one print isn't split."""
    thr = np.median(energy) + 0.35 * (energy.max() - np.median(energy))
    on = energy > thr
    # bridge short gaps of 'off' between 'on'
    i = 0
    while i < len(on):
        if not on[i]:
            j = i
            while j < len(on) and not on[j]:
                j += 1
            if i > 0 and j < len(on) and j - i <= bridge:
                on[i:j] = True
            i = j
        else:
            i += 1
    best, i = (0, 0), 0
    while i < len(on):
        if on[i]:
            j = i
            while j < len(on) and on[j]:
                j += 1
            if j - i > best[1] - best[0]:
                best = (i, j)
            i = j
        else:
            i += 1
    return max(0, best[0] - 20), min(len(energy), best[1] + 20)


def resample_uniform(res_seg, nov_seg, out_rows=None):
    disp = np.cumsum(nov_seg)                       # finger displacement proxy
    if disp[-1] < 1e-6:
        return res_seg
    if out_rows is None:
        out_rows = int(disp[-1] / np.median(nov_seg[nov_seg > 0]))
        out_rows = max(64, min(out_rows, 1200))
    tgt = np.linspace(0, disp[-1], out_rows)
    idx = np.clip(np.searchsorted(disp, tgt), 0, len(res_seg) - 1)
    return res_seg[idx]


def normalize(img):
    ls = np.sqrt(gaussian_filter(img**2, sigma=6)) + 1e-3
    x = np.clip(img / ls, -2.2, 2.2)
    return ((x + 2.2) / 4.4 * 255).astype(np.uint8)


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else "lines.raw"
    out = sys.argv[2] if len(sys.argv) > 2 else "print_stitched"
    img = load(src)
    res = preprocess(img)
    nov = novelty(res)
    energy = finger_energy(res)
    lo, hi = best_segment(energy)
    print(f"lines={len(img)} finger segment={lo}..{hi} ({hi-lo} lines)")
    seg = resample_uniform(res[lo:hi], nov[lo:hi])
    outimg = normalize(seg)
    try:
        from PIL import Image
        Image.fromarray(outimg, "L").save(out + ".png")
        print("saved", out + ".png", outimg.shape)
    except Exception:
        with open(out + ".pgm", "wb") as f:
            f.write(f"P5\n{outimg.shape[1]} {outimg.shape[0]}\n255\n".encode())
            f.write(outimg.tobytes())
        print("saved", out + ".pgm", outimg.shape)


if __name__ == "__main__":
    main()
