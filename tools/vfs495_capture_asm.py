#!/usr/bin/env python3
"""Capture a fingerprint using the TOOL's OWN motion-compensated assembly (IRreconstructImage),
harvested via gdb from IRqualityDetermination. Produces a match-quality image (ridges dark).
Usage: sudo python3 vfs495_capture_asm.py out.pgm
"""
import os, struct, subprocess, sys, tempfile
import numpy as np
RE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUNTIME = RE + "/runtime"

def main():
    out = sys.argv[1]
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tf:
        asm = tf.name
    env = {**os.environ, "LD_LIBRARY_PATH": RUNTIME + "/lib", "VFS_ASM_OUT": asm}
    open(asm, "wb").close()
    cmd = ["gdb", "-q", "-batch", "-x", RUNTIME + "/harvest_assembled.py",
           "--args", RUNTIME + "/bin/validity-sensor-unlocked", "getprintwait", "-doinit"]
    try:
        subprocess.run(cmd, env=env, timeout=int(os.environ.get("VFS_TIMEOUT", "75")),
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        subprocess.run(["pkill", "-9", "-f", "validity-sensor-unlocked"], stderr=subprocess.DEVNULL)
    if os.path.getsize(asm) < 16:
        print("no assembled image (no finger?)", file=sys.stderr); return 10
    d = open(asm, "rb").read(); os.unlink(asm)
    w, h = struct.unpack("<II", d[:8])
    img = np.frombuffer(d[8:8 + w * h], np.uint8).reshape(h, w)
    with open(out, "wb") as f:
        f.write(f"P5\n{w} {h}\n255\n".encode()); f.write(np.ascontiguousarray(img).tobytes())
    print(f"captured assembled {w}x{h} -> {out}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
