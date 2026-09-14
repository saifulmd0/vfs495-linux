#!/usr/bin/env python3
"""Independent VCSFW client: send GET_VERSION (0x01) to the VFS495 and decode the reply.

Read-only. Needs root (or a udev rule) for USB access:  sudo python3 vcsfw_getver.py
"""
import struct
import sys

import usb.core
import usb.util

VID, PID = 0x138A, 0x003F
EP_CMD_OUT, EP_CMD_IN = 0x01, 0x81
CMD_GET_VERSION = 0x01

TARGETS = {1: "ROM", 2: "FPGA", 3: "RTLSIM", 4: "ISS", 5: "FPGADBG"}
PRODUCTS = {1: "Falcon", 2: "Raptor", 3: "Falconusb", 4: "Falconspi", 5: "Raptorusb", 6: "Raptorspi"}


def command(dev, payload, reply_len=0x26, timeout=1000):
    dev.write(EP_CMD_OUT, bytes(payload), timeout)
    reply = bytes(dev.read(EP_CMD_IN, reply_len, timeout))
    if len(reply) < 2:
        raise RuntimeError(f"short reply: {reply.hex()}")
    status = struct.unpack_from("<H", reply)[0]
    return status, reply


def main():
    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if dev is None:
        sys.exit("VFS495 not found")
    dev.set_configuration(1)
    usb.util.claim_interface(dev, 0)
    try:
        status, r = command(dev, [CMD_GET_VERSION])
        print(f"raw    : {r.hex()}")
        print(f"status : 0x{status:04x}")
        if status != 0 or len(r) < 31:
            return
        buildtime, buildnum = struct.unpack_from("<II", r, 2)
        vmajor, vminor, target, product, siliconrev, formalrel, platform, patch = r[10:18]
        security = r[24:26]
        patchsig = struct.unpack_from("<I", r, 26)[0]
        print(f"version: {vmajor}.{vminor} build {buildnum} (buildtime 0x{buildtime:08x})")
        print(f"target : {target} {TARGETS.get(target, '?')}   product: {product} {PRODUCTS.get(product, '?')}")
        print(f"siliconrev={siliconrev} formalrel={formalrel} platform=0x{platform:02x} patch={patch}")
        print(f"security=0x{security.hex()} patchsig=0x{patchsig:08x} iface={r[30]}")
    finally:
        usb.util.release_interface(dev, 0)
        usb.util.dispose_resources(dev)


if __name__ == "__main__":
    main()
