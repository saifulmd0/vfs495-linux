#!/usr/bin/env python3
"""vfs495-match: fingerprint match scoring, offline, using the same libfprint matcher fprintd uses.

  vfs495-match IMG1.pgm IMG2.pgm [IMG3.pgm ...]   score every image against every other
  vfs495-match --template FILE IMG.pgm [...]       score images against an fprintd template
                                                    (e.g. /var/lib/fprint/<user>/virtual_image/0/7)
  sudo vfs495-match --capture N [DIR]             capture N swipes from the sensor into DIR
                                                    (default /run/vfs495-fprint/test), then score them
                                                    against each other and against your enrolled finger
  sudo vfs495-match --enroll IMG.pgm [...]        enroll the given scans (e.g. the ones --capture just
                                                    took) as your right index finger in fprintd

Scores are libfprint/NBIS bozorth3 scores. fprintd accepts a swipe when the score against any
enrolled sub-template is >= 40. Genuine swipes of the same finger typically score 40-150,
different fingers < 15. No sensor is touched unless --capture is used.
"""
import os, sys, re, glob, socket, struct, subprocess, tempfile, threading, time

THRESHOLD = 40
MIN_ROWS = 80
CAPTURE = "/usr/lib/vfs495-fprint/capture.py"

# --- must happen before libfprint is loaded: private socket + score debug output ---
_tmp = tempfile.mkdtemp(prefix="vfs495-match-")
SOCK = _tmp + "/sock"
os.environ["FP_VIRTUAL_IMAGE"] = SOCK
os.environ["G_MESSAGES_DEBUG"] = "libfprint-print"
# glib prints DEBUG-level messages on stdout: capture fd 1, keep a copy for our own output
_orig_stdout = os.dup(1)
_r, _w = os.pipe(); os.dup2(_w, 1); os.close(_w)
_lines = []
def _reader():
    with os.fdopen(_r, "rb", 0) as f:
        for line in f:
            _lines.append(line.decode(errors="replace"))
threading.Thread(target=_reader, daemon=True).start()
def err(msg): sys.stderr.write(msg + "\n"); sys.stderr.flush()
def out(msg): os.write(_orig_stdout, (msg + "\n").encode())

import gi
gi.require_version("FPrint", "2.0")
from gi.repository import FPrint, GLib  # noqa: E402


def read_pgm(p):
    with open(p, "rb") as f:
        if f.readline().strip() != b"P5": raise SystemExit(f"{p}: not a binary PGM (P5)")
        tok = []
        while len(tok) < 3:
            line = f.readline()
            if line.startswith(b"#"): continue
            tok += line.split()
        w, h = int(tok[0]), int(tok[1])
        return w, h, f.read(w * h)


_conn = None
def send_image(img, delay=0.3):
    """Feed one image to the in-process virtual_image device (from a helper thread, over one
    persistent connection so the driver never sees a hang-up mid-operation)."""
    w, h, data = img
    def run():
        global _conn
        time.sleep(delay)
        for _ in range(50):
            try:
                if _conn is None:
                    _conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); _conn.connect(SOCK)
                _conn.sendall(struct.pack("<ii", w, h) + data); return
            except OSError:
                _conn = None; time.sleep(0.1)
    threading.Thread(target=run, daemon=True).start()


def open_device():
    ctx = FPrint.Context()
    ctx.enumerate()
    for d in ctx.get_devices():
        if d.get_driver() == "virtual_image":
            d.open_sync(None); return ctx, d
    raise SystemExit("libfprint virtual_image device not available (is libfprint-2-2 installed?)")


def enroll_from_image(dev, img, name):
    """Build a template from one image (fed for each of the 5 enroll stages)."""
    tmpl = FPrint.Print.new(dev)
    tmpl.set_finger(FPrint.Finger.RIGHT_INDEX); tmpl.set_username("vfs495-match")
    from gi.repository import Gio
    canc = Gio.Cancellable(); n = {"sent": 1}
    def progress(device, completed, print_, user_data, error=None):
        if n["sent"] >= 8: canc.cancel(); return          # image keeps failing minutiae extraction
        if completed < dev.get_nr_enroll_stages(): n["sent"] += 1; send_image(img, 0.2)
    send_image(img)
    try:
        return dev.enroll_sync(tmpl, canc, progress, None)
    except GLib.Error as e:
        err(f"  enroll from {name} failed: {e.message}"); return None


def enroll_from_images(dev, imgs, user):
    """Build a template from several images, cycling through them for the 5 enroll stages."""
    from gi.repository import Gio
    tmpl = FPrint.Print.new(dev)
    tmpl.set_finger(FPrint.Finger.RIGHT_INDEX); tmpl.set_username(user)
    canc = Gio.Cancellable(); n = {"sent": 1}
    def progress(device, completed, print_, user_data, error=None):
        if n["sent"] >= 12: canc.cancel(); return
        if completed < dev.get_nr_enroll_stages():
            send_image(imgs[n["sent"] % len(imgs)], 0.2); n["sent"] += 1
    send_image(imgs[0])
    try:
        return dev.enroll_sync(tmpl, canc, progress, None)
    except GLib.Error as e:
        raise SystemExit(f"enroll failed: {e.message}")


def install_template(dev, files, imgs):
    if os.geteuid() != 0: raise SystemExit("--enroll needs root: sudo vfs495-match --enroll IMG...")
    user = os.environ.get("SUDO_USER") or "root"
    print_ = enroll_from_images(dev, [imgs[f] for f in files], user)
    data = bytes(print_.serialize())
    d = f"/var/lib/fprint/{user}/virtual_image/0"; os.makedirs(d, mode=0o700, exist_ok=True)
    for p in ("/var/lib/fprint", f"/var/lib/fprint/{user}", f"/var/lib/fprint/{user}/virtual_image", d): os.chmod(p, 0o700)
    path = d + "/7"                               # 7 = right index finger in fprintd's file store
    if os.path.exists(path): os.replace(path, path + ".bak")
    with open(path, "wb") as fh: fh.write(data)
    os.chmod(path, 0o644)
    out(f"enrolled right index finger for {user} from {len(files)} scan(s) -> {path}")
    out("check of the new template against those scans:")
    for f in files:
        m, s_ = verify(dev, print_, imgs[f], f); out(f"  {os.path.basename(f):<20} {fmt(m, s_)}")
    subprocess.run(["systemctl", "restart", "fprintd"], stderr=subprocess.DEVNULL)
    out("\nnow test:  fprintd-verify   (wait ~2 s after the prompt, then swipe)")


def verify(dev, template, img, name):
    """Returns (matched, best_score)."""
    del _lines[:]
    send_image(img)
    try:
        res = dev.verify_sync(template, None, None, None)
    except GLib.Error as e:
        err(f"  verify {name}: {e.message}"); return False, -1
    matched = bool(res[0] if isinstance(res, tuple) else res)
    time.sleep(0.05)
    scores = [int(m.group(1)) for l in _lines for m in [re.search(r"score (-?\d+)/(\d+)", l)] if m]
    return matched, (max(scores) if scores else -1)


def fmt(matched, score):
    tag = "MATCH" if matched else "no match"
    return f"{score:4d}/{THRESHOLD}  {tag}"


def capture(n, d):
    if os.geteuid() != 0: raise SystemExit("--capture needs root: sudo vfs495-match --capture N")
    if not os.path.exists("/var/lib/vfs495-fprint/validity-sensor-unlocked"):
        raise SystemExit("HP driver not installed; run: sudo vfs495-setup-hp-driver")
    subprocess.run(["systemctl", "stop", "vfs495-bridge"], stderr=subprocess.DEVNULL)
    os.makedirs(d, exist_ok=True); files = []; tiny = []
    try:
        for i in range(1, n + 1):
            p = f"{d}/swipe-{i}.pgm"
            out(f"[{i}/{n}] get ready... "); time.sleep(1.0)
            out(f"[{i}/{n}] SWIPE NOW (slowly, whole fingertip, one steady motion)")
            r = subprocess.run([sys.executable, CAPTURE, p], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if r.returncode == 0:
                w, h, _ = read_pgm(p)
                if h < MIN_ROWS:
                    out(f"[{i}/{n}] tiny scan {w}x{h}: swipe too short/fast, or the sensor is stuck (see below)")
                    tiny.append(h); os.unlink(p)
                else:
                    out(f"[{i}/{n}] captured {w}x{h} -> {p}"); files.append(p)
            else:
                out(f"[{i}/{n}] nothing captured (missed the swipe?)")
            time.sleep(1.5)
    finally:
        subprocess.run(["systemctl", "start", "vfs495-bridge"], stderr=subprocess.DEVNULL)
    if tiny and not files:
        out("\nEvery scan was tiny. If you did swipe slowly, the sensor is in its stuck state: it returns a few"
            "\nlines and never waits for a finger. Only a FULL POWER-OFF (shut down, wait 10 s, power on) clears it;"
            "\na warm reboot does not.")
    return files


def find_templates():
    user = os.environ.get("SUDO_USER") or os.environ.get("USER") or "*"
    return sorted(glob.glob(f"/var/lib/fprint/{user}/virtual_image/0/*"))


def main(argv):
    args = argv[1:]
    if not args or args[0] in ("-h", "--help"): out(__doc__); return 0
    template_file = None; files = []; enroll = False
    if args[0] == "--capture":
        n = int(args[1]) if len(args) > 1 else 3
        d = args[2] if len(args) > 2 else "/run/vfs495-fprint/test"
        files = capture(n, d)
        if len(files) < 1: raise SystemExit("no captures to score")
        out("")
    else:
        if args[0] == "--template": template_file, args = args[1], args[2:]
        if args and args[0] == "--enroll": enroll, args = True, args[1:]
        files = args
    if not files: raise SystemExit("no images given")
    imgs = {f: read_pgm(f) for f in files}
    for f in list(files):
        if imgs[f][1] < MIN_ROWS:
            err(f"{f}: only {imgs[f][1]} rows, not a usable scan (skipped)"); files.remove(f)
    if not files: raise SystemExit("no usable images")
    ctx, dev = open_device()
    out(f"matcher: libfprint {dev.get_driver()} (NBIS bozorth3), threshold {THRESHOLD}\n")
    if enroll:
        install_template(dev, files, imgs)
        if _conn: _conn.close()
        dev.close_sync(None); return 0

    templates = []
    if template_file: templates.append((template_file, open(template_file, "rb").read()))
    elif argv[1] == "--capture":
        for t in find_templates(): templates.append((t, open(t, "rb").read()))
    for tpath, tdata in templates:
        try:
            tmpl = FPrint.Print.deserialize(tdata)
        except GLib.Error as e:
            err(f"cannot load template {tpath}: {e.message}"); continue
        out(f"against enrolled template {tpath} ({FPrint.Finger(tmpl.get_finger()).value_nick}):")
        for f in files:
            m, s = verify(dev, tmpl, imgs[f], f); out(f"  {os.path.basename(f):<20} {fmt(m, s)}")
        out("")

    if len(files) >= 2:
        out("each image enrolled, verified with every other image:")
        for a in files:
            tmpl = enroll_from_image(dev, imgs[a], a)
            if tmpl is None: continue
            for b in files:
                if a == b: continue
                m, s = verify(dev, tmpl, imgs[b], b)
                out(f"  enroll {os.path.basename(a):<16} verify {os.path.basename(b):<16} {fmt(m, s)}")
    if _conn: _conn.close()
    dev.close_sync(None)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    finally:
        try: os.unlink(SOCK); os.rmdir(_tmp)
        except OSError: pass
