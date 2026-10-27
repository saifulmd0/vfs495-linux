#!/usr/bin/env python3
"""Hardware test of the vfs495 driver through the patched libfprint (no fprintd). Needs root (USB).

    hw_test.py capture N [DIR]   N swipes -> DIR/swipe-NN.pgm (biometric: keep local); retries are listed
    hw_test.py cycles N          open / close N times (session setup + close_notify, no re-enumeration)
    hw_test.py enroll-verify     enroll one finger in memory, then verify it 3x and print the scores

driver/tests/hw_test.sh sets up the environment (patched libfprint, typelibs, a setup.bin).
VFS495_RAW=FILE.npy (driver) dumps the raw lines of each swipe, VFS495_SETUP=PATH picks the setup file.
"""
import os
import sys

import gi

gi.require_version("FPrint", "2.0")
from gi.repository import FPrint, GLib  # noqa: E402

RETRY = {int(getattr(FPrint.DeviceRetry, n)): n for n in ("GENERAL", "TOO_SHORT", "CENTER_FINGER",
                                                          "REMOVE_FINGER", "TOO_FAST")}


CTX = None


def device():
    global CTX
    CTX = FPrint.Context()      # must outlive the device: freeing it runs libusb_exit under the device
    drv = os.environ.get("VFS495_TEST_DRIVER", "vfs495")    # virtual_image: test this script itself
    devs = [d for d in CTX.get_devices() if d.get_driver() == drv]
    if not devs:
        sys.exit("no %s device (wrong libfprint? run through hw_test.sh)" % drv)
    return devs[0]


def is_retry(e):
    return e.domain == GLib.quark_to_string(FPrint.DeviceRetry.quark())


def describe(e):
    if is_retry(e):
        return "retry %s" % RETRY.get(e.code, e.code)
    return "error %s" % e.message


def close(dev):
    try:
        dev.close_sync()
    except GLib.Error as e:          # e.g. the sensor re-enumerated meanwhile
        print("close: " + describe(e))


def capture(n, out):
    os.makedirs(out, exist_ok=True)
    dev = device()
    dev.open_sync()
    ok = 0
    try:
        for i in range(n):
            print("swipe %d/%d ..." % (i + 1, n), flush=True)
            try:
                img = dev.capture_sync(True)
            except GLib.Error as e:
                print("  " + describe(e))
                if is_retry(e):
                    continue
                break                # hard error (e.g. device gone): stop, don't hammer it
            w, h = img.get_width(), img.get_height()
            path = "%s/swipe-%02d.pgm" % (out, i + 1)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(b"P5\n%d %d\n255\n" % (w, h) + bytes(img.get_data()))
            ok += 1
            print("  %dx%d -> %s" % (w, h, path))
    finally:
        close(dev)
    print("%d/%d swipes gave an image" % (ok, n))


def cycles(n):
    dev = device()
    for i in range(n):
        dev.open_sync()
        dev.close_sync()
        print("open/close %d ok" % (i + 1), flush=True)


def enroll_verify():
    dev = device()
    dev.open_sync()
    try:
        tmpl = FPrint.Print.new(dev)
        tmpl.set_finger(FPrint.Finger.RIGHT_INDEX)

        def progress(dev, stage, prt, data, err):
            print("  stage %d/%d%s" % (stage, dev.get_nr_enroll_stages(),
                                      " (" + describe(err) + ")" if err else ""), flush=True)

        print("enroll: swipe the finger %d times" % dev.get_nr_enroll_stages(), flush=True)
        tmpl = dev.enroll_sync(tmpl, None, progress, None)
        for i in range(3):
            print("verify %d/3: swipe the same finger" % (i + 1), flush=True)
            try:
                match, _ = dev.verify_sync(tmpl)
                print("  %s" % ("MATCH" if match else "no match"))
            except GLib.Error as e:
                print("  " + describe(e))
    finally:
        close(dev)


def main():
    a = sys.argv[1:]
    if a[:1] == ["capture"] and len(a) in (2, 3):
        capture(int(a[1]), a[2] if len(a) == 3 else "swipes")
    elif a[:1] == ["cycles"] and len(a) == 2:
        cycles(int(a[1]))
    elif a == ["enroll-verify"]:
        enroll_verify()
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
