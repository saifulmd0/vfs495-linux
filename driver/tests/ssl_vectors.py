#!/usr/bin/env python3
"""Run tools/ssl_session.py (the client verified on hardware) against a simulated sensor with fixed
randomness; write every input and wire message to a GKeyFile for tests/test_ssl.c to replay.

    python3 ssl_vectors.py OUT.ini
"""
import hashlib
import os
import random
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../tools"))
import ssl_session as S  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402

rng = random.Random(495)
drawn = []


def token_bytes(n):
    b = bytes(rng.getrandbits(8) for _ in range(n))
    drawn.append(b)
    return b


S.secrets.token_bytes = token_bytes
modulus_le = rsa.generate_private_key(65537, 2048).public_key().public_numbers().n.to_bytes(256, "little")
server_random = bytes(range(32))
sh_hs = (b"\x02\x00\x00\x46\x03\x00" + server_random + b"\x20" + bytes(range(100, 132)) + b"\x00\x44\x00"
         + b"\x0e\x00\x00\x00")
server_hello = b"\x16\x03\x00" + struct.pack(">H", len(sh_hs)) + sh_hs
version_reply = b"\x00\x00" + bytes(range(0x40, 0x66))


class FakeSensor:
    """Answers like the sensor: ServerHello, then CCS + Finished, then encrypted replies."""

    def __init__(self):
        self.out, self.replies, self.srv = [], [], None

    def write(self, ep, data, to=None):
        self.out.append(bytes(data))

    def read(self, ep, n, to=None):
        k = len(self.out)
        if k == 1:
            r = server_hello
        elif k == 2:
            client_random, premaster = drawn[0], b"\x03\x00" + drawn[1]
            master = S.ssl3_prf(premaster, client_random, server_random, 48)
            kb = S.ssl3_prf(master, server_random, client_random, 136)
            self.srv = S.SSLState(kb)                       # server side: send with the s* keys
            self.srv.cmac, self.srv.ckey, self.srv.civ = kb[20:40], kb[72:104], kb[120:136]
            ch_hs, cke_hs = self.out[0][8:], self.out[1][8:8 + 4 + 256]
            fin = b"\x14\x00\x00\x24" + S.ssl3_finished(master, ch_hs + sh_hs + cke_hs, S.LABEL_SRVR)
            r = b"\x14\x03\x00\x00\x01\x01" + self.srv.encrypt_record(0x16, fin)
        elif k == 3:
            r = self.srv.encrypt_record(0x17, version_reply)
        else:
            r = self.srv.encrypt_record(0x15, b"\x01\x00")
        self.replies.append(r)
        return r


dev = FakeSensor()
st = S.handshake(dev, modulus_le)
assert S.command(dev, st, b"\x01") == version_reply
assert S.close_session(dev, st)

pad = b"".join(b for b in drawn[2:] if b != b"\x00")      # rsa_encrypt draws non-zero bytes one by one
assert len(pad) == 256 - 3 - 48
flash = bytearray(rng.getrandbits(8) for _ in range(0x1000))
flash[13:33] = b"\xff\x05" + struct.pack("<II", 0x1800, 16) + b"\xff\x0a" + struct.pack("<II", 0x1200, 256)
flash[33] = 0
flash[0x200:0x300] = modulus_le

v = {"modulus": modulus_le, "client_random": drawn[0], "premaster": b"\x03\x00" + drawn[1], "pad": pad,
     "hello": dev.out[0], "server_hello": dev.replies[0], "flight": dev.out[1], "server_fin": dev.replies[1],
     "cmd": dev.out[2], "cmd_reply": dev.replies[2], "cmd_plain": version_reply,
     "close": dev.out[3], "close_reply": dev.replies[3], "flash": bytes(flash)}
with open(sys.argv[1], "w") as f:
    f.write("[v]\n" + "".join("%s=%s\n" % (k, b.hex()) for k, b in v.items()))
print("vectors: handshake + GetVersion + close_notify, sha256 %s" % hashlib.sha256(dev.out[1]).hexdigest()[:16])
