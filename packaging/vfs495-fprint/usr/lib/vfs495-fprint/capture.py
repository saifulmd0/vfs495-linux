#!/usr/bin/env python3
"""vfs495 capture: drive HP's validity-sensor (which holds the sensor's secure session)
under gdb and harvest its motion-compensated assembled fingerprint. Output: PGM.
Usage: vfs495-capture OUT.pgm     (root)     env: VFS_TIMEOUT (s, default 75)"""
import os, struct, subprocess, sys, tempfile
HP = "/var/lib/vfs495-fprint"          # HP binary + shim libs (installed by setup-hp-driver.sh)
LIB = "/usr/lib/vfs495-fprint"
def main():
    if len(sys.argv) < 2: sys.exit("usage: vfs495-capture OUT.pgm")
    out = sys.argv[1]
    binp = HP + "/validity-sensor-unlocked"
    if not os.path.exists(binp):
        sys.exit("HP driver not installed. Run: sudo vfs495-setup-hp-driver")
    fd, asm = tempfile.mkstemp(suffix=".bin"); os.close(fd)
    env = {**os.environ, "LD_LIBRARY_PATH": HP + "/lib", "VFS_ASM_OUT": asm}
    cmd = ["gdb", "-q", "-batch", "-x", LIB + "/harvest_assembled.py",
           "--args", binp, "getprintwait", "-doinit"]
    try:
        subprocess.run(cmd, env=env, timeout=int(os.environ.get("VFS_TIMEOUT", "75")),
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        subprocess.run(["pkill", "-9", "-f", "validity-sensor-unlocked"], stderr=subprocess.DEVNULL)
    try:
        d = open(asm, "rb").read()
    finally:
        try: os.unlink(asm)
        except OSError: pass
    if len(d) < 16:
        print("no finger captured", file=sys.stderr); return 10
    w, h = struct.unpack("<II", d[:8]); px = d[8:8 + w * h]
    with open(out, "wb") as f:
        f.write(f"P5\n{w} {h}\n255\n".encode()); f.write(px)
    print(f"captured {w}x{h} -> {out}"); return 0
if __name__ == "__main__": sys.exit(main())
