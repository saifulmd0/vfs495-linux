#!/usr/bin/env python3
"""Test whether the VFS495 requires the SSL session after patch upload.

Replays the captured pre-SSL init (GetVersion, GetStartInfo, patch, SPI reads,
patch) then sends plaintext GetConfiguration (0x15) and GetFingerprint (0x15 blob)
and reports whether the sensor answers or denies. Read-only / RAM patches only.
Run: sudo python3 test_nossl.py
"""
import json
import os
import sys
import time

import usb.core
import usb.util

VID, PID = 0x138A, 0x003F
EP_OUT, EP_CMD_IN, EP_DATA_IN = 0x01, 0x81, 0x82


def cmd(dev, payload, reply=0x400, timeout=2000, read_data=False):
    dev.write(EP_OUT, bytes(payload), timeout)
    r = bytes(dev.read(EP_CMD_IN, reply, timeout))
    data = b""
    if read_data:
        try:
            while True:
                chunk = bytes(dev.read(EP_DATA_IN, 16384, 500))
                data += chunk
                if len(chunk) < 16384:
                    break
        except usb.core.USBError:
            pass
    return r, data


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    init = [bytes.fromhex(h) for h in json.load(open(here + "/../captures/init_cmds.json"))]

    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if dev is None:
        sys.exit("VFS495 not found")
    dev.set_configuration(1)
    usb.util.claim_interface(dev, 0)
    try:
        print("== replaying init (patches + SPI reads) ==")
        for i, c in enumerate(init):
            try:
                r, _ = cmd(dev, c, read_data=(c[0] == 0x1F))
                st = int.from_bytes(r[:2], "little") if len(r) >= 2 else -1
                print(f"  init[{i}] cmd=0x{c[0]:02x} -> status=0x{st:04x} replylen={len(r)}")
            except usb.core.USBError as e:
                print(f"  init[{i}] cmd=0x{c[0]:02x} USBError {e}")
            time.sleep(0.02)

        print("\n== plaintext GetConfiguration (0x15) after patch, NO SSL ==")
        try:
            r, data = cmd(dev, [0x15], read_data=True)
            st = int.from_bytes(r[:2], "little")
            print(f"  reply status=0x{st:04x} replylen={len(r)} ep2_bytes={len(data)}")
            print(f"  verdict: {'DENIED (SSL required)' if st == 0x0404 else 'ACCEPTED (no SSL needed!)'}")
        except usb.core.USBError as e:
            print(f"  USBError {e}")
    finally:
        usb.util.release_interface(dev, 0)
        usb.util.dispose_resources(dev)


if __name__ == "__main__":
    main()
