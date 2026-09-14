#!/usr/bin/env python3
"""vfs495 bridge (event-driven): stays completely idle until fprintd's device reports
finger-needed=true (a verify or enroll is waiting for a swipe), then runs ONE capture on
the real sensor and delivers the image to libfprint's virtual_image socket. This avoids
hammering the sensor when nobody is authenticating (which degrades it)."""
import os, socket, struct, subprocess, sys, threading, time
import dbus, dbus.mainloop.glib
from gi.repository import GLib

SOCK = os.environ.get("FP_VIRTUAL_IMAGE", "/run/fprint/virtimg_sock")
CAPTURE = "/usr/lib/vfs495-fprint/capture.py"
BUS_NAME, DEV_IFACE = "net.reactivated.Fprint", "net.reactivated.Fprint.Device"
PROPS = "org.freedesktop.DBus.Properties"
state = {"capturing": False}

def log(m): print("[vfs495-bridge] " + m, file=sys.stderr, flush=True)

def read_pgm(p):
    with open(p, "rb") as f:
        assert f.readline().strip() == b"P5"; w, h = map(int, f.readline().split()); f.readline()
        return w, h, f.read(w * h)

def deliver(w, h, data):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(SOCK)
    s.sendall(struct.pack("<ii", w, h) + data); s.close()

def capture_and_deliver():
    out = "/run/vfs495-fprint/cap.pgm"; os.makedirs("/run/vfs495-fprint", exist_ok=True)
    try:
        for attempt in range(2):   # a swipe can straddle the window; try twice
            r = subprocess.run([sys.executable, CAPTURE, out], env={**os.environ, "VFS_TIMEOUT": "75"},
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if r.returncode == 0:
                try:
                    deliver(*read_pgm(out)); log("delivered scan"); break
                except OSError as e:
                    log(f"deliver failed: {e}"); break
            log("no finger captured" + (", retrying" if attempt == 0 else ""))
    finally:
        try: os.unlink(out)
        except OSError: pass
        state["capturing"] = False

def trigger(reason):
    if state["capturing"]: return
    state["capturing"] = True
    log(f"finger needed ({reason}) -> capturing; swipe now")
    threading.Thread(target=capture_and_deliver, daemon=True).start()

def on_props_changed(iface, changed, invalidated, path=None):
    if iface != DEV_IFACE: return
    if bool(changed.get("finger-needed", False)): trigger("finger-needed")

def on_verify_selected(*args, path=None): trigger("verify started")

def main():
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    bus.add_signal_receiver(on_props_changed, signal_name="PropertiesChanged", dbus_interface=PROPS,
                            bus_name=BUS_NAME, path_keyword="path")
    bus.add_signal_receiver(on_verify_selected, signal_name="VerifyFingerSelected", dbus_interface=DEV_IFACE,
                            bus_name=BUS_NAME, path_keyword="path")
    # if a scan is already pending at startup, serve it
    def check_initial():
        try:
            mgr = dbus.Interface(bus.get_object(BUS_NAME, "/net/reactivated/Fprint/Manager"), "net.reactivated.Fprint.Manager")
            for dev in mgr.GetDevices():
                p = dbus.Interface(bus.get_object(BUS_NAME, dev), PROPS)
                if bool(p.Get(DEV_IFACE, "finger-needed")): trigger("pending at startup")
        except dbus.DBusException: pass
        return False
    GLib.timeout_add(1500, check_initial)
    log("idle; waiting for fprintd to need a finger")
    GLib.MainLoop().run()

if __name__ == "__main__": main()
