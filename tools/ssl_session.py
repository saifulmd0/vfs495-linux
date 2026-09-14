#!/usr/bin/env python3
"""VFS495 proprietary-SSLv3 client PoC: establish the secure session with the sensor.

Implements driver/SSL_PROTOCOL.md. KDF validated against gdb dumps (kdf_vector.json).
Goal: complete the handshake (sensor accepts our Finished), then the capture command
can be sent as AppData. Read-only / RAM patches. Run: sudo python3 ssl_session.py
"""
import json
import os
import struct
import sys

import hashlib
import secrets

import usb.core
import usb.util
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HERE = os.path.dirname(os.path.abspath(__file__))
CAP = HERE + "/../captures"
VID, PID = 0x138A, 0x003F
EP_OUT, EP_CMD_IN = 0x01, 0x81


# ---- crypto ---------------------------------------------------------------
def ssl3_prf(secret, seed_a, seed_b, nbytes):
    out, i = b"", 0
    while len(out) < nbytes:
        salt = bytes([0x41 + i]) * (i + 1)
        out += hashlib.md5(secret + hashlib.sha1(salt + secret + seed_a + seed_b).digest()).digest()
        i += 1
    return out[:nbytes]


def rsa_encrypt_reversed(modulus_be, exp, msg):
    n = int.from_bytes(modulus_be, "little")   # modulus is stored little-endian (verified)
    k = len(modulus_be)
    # PKCS#1 v1.5 type 2
    ps = b""
    while len(ps) < k - 3 - len(msg):
        b = secrets.token_bytes(1)
        if b != b"\x00":
            ps += b
    em = b"\x00\x02" + ps + b"\x00" + msg
    c = pow(int.from_bytes(em, "big"), exp, n)
    cb = c.to_bytes(k, "big")
    return cb   # wire = big-endian C (double byte-reversal in the driver cancels; verified)


def ssl3_finished(master, handshake_msgs, label):
    def h(algo, pad_len):
        pad1 = b"\x36" * pad_len
        pad2 = b"\x5c" * pad_len
        inner = algo(handshake_msgs + label + master + pad1).digest()
        return algo(master + pad2 + inner).digest()
    return h(hashlib.md5, 48) + h(hashlib.sha1, 40)


class SSLState:
    def __init__(self, keyblock):
        self.cmac = keyblock[0:20]
        self.smac = keyblock[20:40]
        self.ckey = keyblock[40:72]
        self.skey = keyblock[72:104]
        self.civ = keyblock[104:120]
        self.siv = keyblock[120:136]
        self.send_seq = 0
        self.recv_seq = 0

    def mac(self, key, seq, rtype, data):
        # Validity SSLv3 MAC variant: length is NOT included (only seq + type + data).
        pad1, pad2 = b"\x36" * 40, b"\x5c" * 40
        hdr = struct.pack(">Q", seq) + bytes([rtype])
        inner = hashlib.sha1(key + pad1 + hdr + data).digest()
        return hashlib.sha1(key + pad2 + inner).digest()

    def encrypt_record(self, rtype, data):
        m = self.mac(self.cmac, self.send_seq, rtype, data)
        self.send_seq += 1
        body = data + m
        padlen = 16 - (len(body) % 16)
        body += bytes([padlen - 1]) * padlen
        enc = Cipher(algorithms.AES(self.ckey), modes.CBC(self.civ)).encryptor()
        ct = enc.update(body) + enc.finalize()
        self.civ = ct[-16:]  # SSLv3 CBC IV chaining
        return bytes([rtype, 3, 0]) + struct.pack(">H", len(ct)) + ct


# ---- usb ------------------------------------------------------------------
TRAFFIC = []
def send(dev, payload, to=3000):
    TRAFFIC.append(("OUT", bytes(payload)))
    dev.write(EP_OUT, bytes(payload), to)


def recv(dev, n=0x400, to=3000):
    r = bytes(dev.read(EP_CMD_IN, n, to))
    TRAFFIC.append(("IN01", r))
    return r


def tunnel(record):
    return bytes([0x11]) + struct.pack("<H", len(record)) + record


def main():
    init = [bytes.fromhex(h) for h in json.load(open(CAP + "/init_cmds.json"))]
    tpl = json.load(open(CAP + "/hs_templates.json"))
    modulus = open(CAP + "/rsa_modulus.bin", "rb").read()

    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if dev is None:
        sys.exit("VFS495 not found")
    dev.set_configuration(1)
    usb.util.claim_interface(dev, 0)
    try:
        # 1. init (patches + SPI reads)
        for c in init:
            send(dev, c)
            recv(dev)
            if c[0] == 0x1F:
                try:
                    while True:
                        if len(bytes(dev.read(0x82, 16384, 400))) < 16384:
                            break
                except usb.core.USBError:
                    pass
        print("init ok")

        # 2. ClientHello (template with our client_random at body offset 11..43)
        ch = bytearray(bytes.fromhex(tpl["clienthello"]))  # 11 <len16> <record>
        rec_ch = ch[3:]                                    # TLS record
        client_random = secrets.token_bytes(32)
        rec_ch[11:43] = client_random
        ch_hs = bytes(rec_ch[5:])                          # handshake msg (no record hdr)
        # precompute the slow RSA BEFORE sending, to minimize ServerHello->flight latency
        premaster = b"\x03\x00" + secrets.token_bytes(46)
        enc_pm = rsa_encrypt_reversed(modulus, 0x10001, premaster)
        cke_hs = b"\x10\x00\x01\x00" + enc_pm
        cke_rec = b"\x16\x03\x00" + struct.pack(">H", len(cke_hs)) + cke_hs
        send(dev, tunnel(bytes(rec_ch)))
        sh = recv(dev)
        print("serverhello", sh[:12].hex(), "len", len(sh))
        # whole record body = ServerHello + ServerHelloDone (both hashed for Finished)
        sh_reclen = int.from_bytes(sh[3:5], "big")
        sh_hs = sh[5:5 + sh_reclen]
        server_random = sh[11:43]

        # 3. keys (RSA/CKE already computed above)
        master = ssl3_prf(premaster, client_random, server_random, 48)
        keyblock = ssl3_prf(master, server_random, client_random, 136)
        st = SSLState(keyblock)

        # 5. Finished (over ClientHello + ServerHello + ClientKeyExchange handshake msgs)
        hs_msgs = ch_hs + sh_hs + cke_hs
        # label is hashed as the raw little-endian int 0x434c4e54 -> bytes 54 4e 4c 43
        fin_body = ssl3_finished(master, hs_msgs, struct.pack("<I", 0x434C4E54))
        fin_hs = b"\x14\x00\x00\x24" + fin_body
        ccs = b"\x14\x03\x00\x00\x01\x01"
        fin_rec = st.encrypt_record(0x16, fin_hs)

        # second tunnel: CKE + CCS + encrypted Finished
        # full second flight in ONE tunnel, exactly like the tool
        send(dev, tunnel(cke_rec + ccs + fin_rec))
        try:
            resp = recv(dev, 0x400, 3000)
            print("  server response:", resp.hex())
            if resp[0] == 0x14 or resp[0] == 0x16:
                print("  HANDSHAKE OK - server sent CCS/Finished!")
            elif resp[0] == 0x15:
                print("  ALERT desc 0x%02x" % resp[-1])
        except Exception as e:
            print("  no response:", e)
    finally:
        import json as _j
        _j.dump([(d, b.hex()) for d, b in TRAFFIC], open(CAP + "/my_session.json", "w"))
        usb.util.release_interface(dev, 0)
        usb.util.dispose_resources(dev)


if __name__ == "__main__":
    main()
