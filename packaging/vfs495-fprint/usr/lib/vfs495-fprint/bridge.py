#!/usr/bin/env python3
"""vfs495 bridge: capture from the real sensor and feed libfprint's virtual_image
device (fprintd) over FP_VIRTUAL_IMAGE. Runs as a root service. Loops forever."""
import os, socket, struct, subprocess, sys, time
SOCK = os.environ.get("FP_VIRTUAL_IMAGE", "/run/fprint/virtimg_sock")
def read_pgm(p):
    with open(p, "rb") as f:
        assert f.readline().strip() == b"P5"; w, h = map(int, f.readline().split()); f.readline()
        return w, h, f.read(w * h)
def capture():
    out = "/run/vfs495-fprint/cap.pgm"; os.makedirs("/run/vfs495-fprint", exist_ok=True)
    r = subprocess.run([sys.executable, "/usr/lib/vfs495-fprint/capture.py", out],
                       env={**os.environ, "VFS_TIMEOUT": "75"}, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if r.returncode != 0: return None
    try: return read_pgm(out)
    finally:
        try: os.unlink(out)
        except OSError: pass
def send(w, h, data):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(SOCK)
    s.sendall(struct.pack("<ii", w, h) + data); s.close()
while True:
    cap = capture()
    if cap is None: time.sleep(0.5); continue
    try: send(*cap); print("[vfs495-bridge] delivered scan", file=sys.stderr)
    except OSError: time.sleep(1)   # fprintd not listening right now; image dropped
    time.sleep(0.3)
