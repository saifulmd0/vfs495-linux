#!/usr/bin/env python3
"""Capture one fingerprint from the VFS495 via the proprietary SSL+capture path,
reconstruct it, and output a clean 8-bit grayscale fingerprint (ridges dark).

Uses HP's validity-sensor (which does the SSL session + capture correctly) under
gdb to harvest the descrambled scan lines, then the validated reconstruction
pipeline. This is the community approach: delegate SSL+capture to the proprietary
binary, keep decode/descramble/stitch open.

Usage:
    sudo python3 vfs495_capture.py [out.pgm]
Env:
    VFS_TIMEOUT  gdb/capture timeout seconds (default 70)
Exit: 0 on a good capture, 10 on no-finger/too-short, 1 on error.
"""
import os
import subprocess
import sys
import tempfile

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import reconstruct as R  # noqa: E402

RE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUNTIME = RE + "/runtime"


def harvest_lines(lines_out):
    """Run validity-sensor getprintwait -doinit under gdb, harvesting descrambled lines."""
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = RUNTIME + "/lib"
    env["VFS_LINES_OUT"] = lines_out
    open(lines_out, "wb").close()
    cmd = [
        "gdb", "-q", "-batch", "-x", RUNTIME + "/harvest_lines.py",
        "--args", RUNTIME + "/bin/validity-sensor-unlocked", "getprintwait", "-doinit",
    ]
    try:
        subprocess.run(cmd, env=env, timeout=int(os.environ.get("VFS_TIMEOUT", "75")),
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        subprocess.run(["pkill", "-9", "-f", "validity-sensor-unlocked"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return os.path.getsize(lines_out)  # lines appended as captured; partial data still usable


def reconstruct(lines_raw):
    """lines.raw -> normalized grayscale fingerprint image (ridges dark). Returns uint8 array or None."""
    img = R.load(lines_raw)
    if img.shape[0] < 200:
        return None
    res = R.preprocess(img)
    nov = R.novelty(res)
    energy = R.finger_energy(res)
    lo, hi = R.best_segment(energy)
    if hi - lo < VFS495_MIN_LINES:
        return None
    seg = R.resample_uniform(res[lo:hi], nov[lo:hi])
    seg = seg[:, :200]                         # main image columns only (200..263 = aux/nav sub-image)
    out = R.normalize(seg)                     # 0..255, ridges currently light
    out = isotropic_v(out)                     # normalize vertical ridge spacing to horizontal (swipe-speed invariant)
    out = 255 - out                            # invert -> ridges dark (fingerprint convention)
    return np.ascontiguousarray(out)


def _ridge_period(a, axis):
    x = a.astype(np.float32) - a.mean()
    F = np.abs(np.fft.rfft(x, axis=axis)).mean(axis=1 - axis)
    F[:3] = 0
    peak = int(np.argmax(F[:len(F) // 2]))
    return a.shape[axis] / peak if peak else None


def isotropic_v(img):
    """Resample the swipe (vertical) axis so its ridge spacing equals the horizontal one.
    Cancels swipe-speed variation -> consistent geometry across captures."""
    from PIL import Image
    hp, vp = _ridge_period(img, 1), _ridge_period(img, 0)
    if not hp or not vp or vp <= hp:
        return img
    new_h = max(80, int(round(img.shape[0] * hp / vp)))
    return np.array(Image.fromarray(img).resize((img.shape[1], new_h), Image.LANCZOS))


VFS495_MIN_LINES = 150


def write_pgm(path, img):
    with open(path, "wb") as f:
        f.write(f"P5\n{img.shape[1]} {img.shape[0]}\n255\n".encode())
        f.write(img.tobytes())


def main():
    out_pgm = sys.argv[1] if len(sys.argv) > 1 else None
    attempts = int(os.environ.get("VFS_ATTEMPTS", "8"))
    with tempfile.NamedTemporaryFile(suffix=".raw", delete=False) as tf:
        lines_raw = tf.name
    try:
        img = None
        for a in range(attempts):
            n = harvest_lines(lines_raw)
            if n < 4:
                print(f"attempt {a+1}: sensor init failed", file=sys.stderr)
                continue
            img = reconstruct(lines_raw)
            if img is not None:
                break
            print(f"attempt {a+1}: no finger — keep swiping", file=sys.stderr)
        if img is None:
            print("capture: no finger detected after retries — swipe steadily during capture",
                  file=sys.stderr)
            return 10
        if out_pgm:
            write_pgm(out_pgm, img)
            print(f"captured {img.shape[1]}x{img.shape[0]} -> {out_pgm}")
        else:
            # raw grayscale to stdout, preceded by "WxH\n"
            sys.stdout.write(f"{img.shape[1]}x{img.shape[0]}\n")
            sys.stdout.flush()
            sys.stdout.buffer.write(img.tobytes())
        return 0
    finally:
        try:
            os.unlink(lines_raw)
        except OSError:
            pass


if __name__ == "__main__":
    sys.exit(main())
