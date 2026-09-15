#!/usr/bin/env python3
"""vfs495 bridge (event-driven): stays completely idle until fprintd's device reports
finger-needed=true (a verify or enroll is waiting for a swipe), then runs ONE capture on
the real sensor and delivers the image to libfprint's virtual_image socket. When fprintd
stops needing a finger (timeout, cancel, done) a still-running capture is cancelled, so the
sensor is never held longer than an authentication actually lasts."""
import os, signal, socket, struct, subprocess, sys, threading, time
import dbus, dbus.mainloop.glib
from gi.repository import GLib

SOCK = os.environ.get("FP_VIRTUAL_IMAGE", "/run/fprint/virtimg_sock")
CAPTURE = "/usr/lib/vfs495-fprint/capture.py"
RUN = "/run/vfs495-fprint"                  # tmpfs, root only; last.pgm = most recent capture (debugging)
BUS_NAME, DEV_IFACE = "net.reactivated.Fprint", "net.reactivated.Fprint.Device"
PROPS = "org.freedesktop.DBus.Properties"
lock = threading.Lock()
state = {"proc": None, "capturing": False, "wanted": False, "gen": 0}

def log(m): print("[vfs495-bridge] " + m, file=sys.stderr, flush=True)

def read_pgm(p):
    with open(p, "rb") as f:
        assert f.readline().strip() == b"P5"; w, h = map(int, f.readline().split()); f.readline()
        return w, h, f.read(w * h)

def deliver(w, h, data):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(SOCK)
    s.sendall(struct.pack("<ii", w, h) + data); s.close()

def run_capture(out):
    """One capture attempt. Returns True if an image was written to `out`."""
    p = subprocess.Popen([sys.executable, CAPTURE, out], env={**os.environ, "VFS_TIMEOUT": "70"},
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    with lock: state["proc"] = p
    rc = p.wait()
    with lock: state["proc"] = None
    return rc == 0

def kill_capture():
    with lock: p = state["proc"]
    if p and p.poll() is None:
        try: os.killpg(p.pid, signal.SIGTERM)
        except OSError: pass
        subprocess.run(["pkill", "-9", "-f", "validity-sensor-unlocked"], stderr=subprocess.DEVNULL)

def capture_and_deliver(gen):
    os.makedirs(RUN, mode=0o700, exist_ok=True)
    out, last = RUN + "/cap.pgm", RUN + "/last.pgm"
    t0 = time.monotonic()
    try:
        for attempt in range(2):                       # a swipe can straddle the window; try twice
            ok = run_capture(out)
            if state["gen"] != gen or not state["wanted"]:
                log("capture cancelled (fprintd no longer waiting)"); return
            if ok:
                try:
                    img = read_pgm(out); os.replace(out, last)
                    deliver(*img); log(f"delivered scan {img[0]}x{img[1]} after {time.monotonic()-t0:.1f}s"); return
                except OSError as e:
                    log(f"deliver failed: {e}"); return
            log("no finger captured" + (", retrying" if attempt == 0 else " (give up)"))
    finally:
        try: os.unlink(out)
        except OSError: pass
        state["capturing"] = False

def on_needed(reason):
    state["wanted"] = True
    if state["capturing"]: return
    state["capturing"] = True; state["gen"] += 1
    log(f"finger needed ({reason}) -> capturing; swipe now")
    threading.Thread(target=capture_and_deliver, args=(state["gen"],), daemon=True).start()

def on_not_needed():
    if not state["wanted"]: return
    state["wanted"] = False
    if state["capturing"]:
        state["gen"] += 1; kill_capture()

def on_props_changed(iface, changed, invalidated, path=None):
    if iface != DEV_IFACE or "finger-needed" not in changed: return
    if bool(changed["finger-needed"]): on_needed("finger-needed")
    else: on_not_needed()

def on_verify_selected(*args, path=None): on_needed("verify started")

def main():
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    bus.add_signal_receiver(on_props_changed, signal_name="PropertiesChanged", dbus_interface=PROPS,
                            bus_name=BUS_NAME, path_keyword="path")
    bus.add_signal_receiver(on_verify_selected, signal_name="VerifyFingerSelected", dbus_interface=DEV_IFACE,
                            bus_name=BUS_NAME, path_keyword="path")
    def check_initial():                                # a scan already pending at startup?
        try:
            mgr = dbus.Interface(bus.get_object(BUS_NAME, "/net/reactivated/Fprint/Manager"), "net.reactivated.Fprint.Manager")
            for dev in mgr.GetDevices():
                p = dbus.Interface(bus.get_object(BUS_NAME, dev), PROPS)
                if bool(p.Get(DEV_IFACE, "finger-needed")): on_needed("pending at startup")
        except dbus.DBusException: pass
        return False
    GLib.timeout_add(1500, check_initial)
    log("idle; waiting for fprintd to need a finger")
    GLib.MainLoop().run()

if __name__ == "__main__": main()
