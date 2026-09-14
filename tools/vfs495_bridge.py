#!/usr/bin/env python3
"""Bridge: capture from the real VFS495 (proprietary SSL+capture path) and feed the
reconstructed image into libfprint's virtual_image driver over its socket.

libfprint (enroll/identify/fprintd with FP_VIRTUAL_IMAGE=<sock>) is the LISTENER;
this bridge is the CLIENT. For each scan libfprint needs, we capture once and send
    <int32 width LE><int32 height LE><width*height bytes grayscale>.

Usage:
    sudo FP_VIRTUAL_IMAGE=/tmp/vfs.sock python3 vfs495_bridge.py [--count N] [--file img.pgm]
    --file  send an existing PGM instead of capturing (for plumbing tests)
    --count how many scans to send (default: loop until the socket closes)
"""
import os
import socket
import struct
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))


def read_pgm(path):
    with open(path, "rb") as f:
        assert f.readline().strip() == b"P5"
        w, h = map(int, f.readline().split())
        f.readline()  # maxval
        return w, h, f.read(w * h)


def capture():
    """Capture one fingerprint via the tool's motion-compensated assembly; (w,h,bytes) or None."""
    out = "/tmp/vfs495_cap.pgm"
    r = subprocess.run([sys.executable, HERE + "/vfs495_capture_asm.py", out],
                       env={**os.environ, "VFS_TIMEOUT": "75"})
    if r.returncode != 0:
        return None
    return read_pgm(out)


def send_image(sock_path, w, h, data):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(sock_path)
    s.sendall(struct.pack("<ii", w, h) + data)
    s.close()


def main():
    sock = os.environ.get("FP_VIRTUAL_IMAGE")
    if not sock:
        sys.exit("set FP_VIRTUAL_IMAGE=<socket path>")
    args = sys.argv[1:]
    count = None
    fixed_file = None
    if "--count" in args:
        count = int(args[args.index("--count") + 1])
    if "--file" in args:
        fixed_file = args[args.index("--file") + 1]

    sent = 0
    while count is None or sent < count:
        if fixed_file:
            w, h, data = read_pgm(fixed_file)
        else:
            print(f"[bridge] scan {sent + 1}: swipe your finger...", file=sys.stderr)
            cap = capture()
            if cap is None:
                print("[bridge] capture failed; retrying", file=sys.stderr)
                continue
            w, h, data = cap
        try:
            send_image(sock, w, h, data)
            sent += 1
            print(f"[bridge] sent image {sent} ({w}x{h})", file=sys.stderr)
        except (ConnectionRefusedError, FileNotFoundError, BrokenPipeError):
            print("[bridge] libfprint socket not ready/closed", file=sys.stderr)
            time.sleep(1)
            if fixed_file:
                break
        time.sleep(0.3)


if __name__ == "__main__":
    main()
