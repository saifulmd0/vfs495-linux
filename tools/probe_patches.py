#!/usr/bin/env python3
"""Which of HP's firmware patches does the VFS495 actually need, and what does each one enable?

    sudo python3 probe_patches.py [STEP...]   (default: R F R G R H R G; VFS495_CAPTURES as for ssl_session.py)
    python3 probe_patches.py --plan [STEP...]  print what each step sends; no sensor access, no root

Steps. Each variant unloads leftover patches with 1a first, like HP does. Patches by size: 693 B and 1301 B
are the init patches, 405 B / 2581 B / 1301 B the setup ones (docs/FINDINGS.md):
  R  force a clean sensor: open a session, drop it without close_notify, send a plaintext command. The sensor
     answers with an alert and resets itself (RAM cleared); wait for the re-enumeration.
  A  no patches at all: init without the 06 commands, setup without 06 / 1a     -> ROM only
  B  only the 693 B init patch (stored verbatim in HP's package), setup without 06 / 1a
  C  both init patches as recorded, setup without 06 / 1a                     -> are the setup patches needed?
  D  no init patches, setup as recorded (with its 06 / 1a)                    -> are the init patches needed?
  E  only the 1301 B init patch, setup without 06 / 1a                        -> is the 693 B patch needed?
  F  init as recorded, setup without the 2581 B patch                         -> what does 2581 B enable?
  G  init as recorded, setup without the 405 B patches                        -> what does 405 B enable?
  H  init as recorded, setup without the 1301 B reload                        -> is HP's reload needed?
  T  like C, but the 2691 B / 3033 B configs without TLV types 23 and 27 (MODIFIED config, see below)
                                                                               -> are those the types the ROM lacks?
  U  init as recorded, setup without the 2581 B patch, configs without the TLV types the ROM lacks (19/20/29/7
     in the 2666 B one, 23/27 in the 2691 / 3033 B ones; MODIFIED)            -> can a ROM-only config capture?
  V  like U, without the 2666 B config                                        -> is that config needed at all?
  W  like U, arming config also without type 24 (338 B)                       -> in case the ROM lacks 24 too
  P  no patches, no session: init without 06 / 1f, every setup command in plaintext, configs stripped as in U
                                                                               -> can the bare ROM capture?
  M  init as recorded (693 + 1301 B), setup without ANY patch or 1a (no 405 B, no 2581 B, no 1301 B reload),
     without the 2666 B config, configs stripped as in U (MODIFIED)           -> V and G combined: the minimum?
Run 9 (T7): G = H within run-to-run noise (calibration reads, replies, swipe baseline/contrast/noise, NBIS);
V captured; U / W fail after the stripped 2666 B config; P's first plaintext 02 is refused (0404).
The default run, each step from a freshly reset sensor: where exactly F's 405 B upload fails (R F), and G's
finger detection and print quality against H as the control (R G R H R G; use VFS495_PROBE_SWIPES=3 and
VFS495_PROBE_TRACE, score the prints with vfs495-match). A and E (run 6) showed the 693 B patch is needed; a timed-out flash read no
longer stops them, they go on with the RSA key read by an earlier step.

Results so far (one sensor, docs/FINDINGS.md "Which HP patches does the sensor need?"):
- Without the 1301 B patch, the ROM refuses the 0x11 handshake tunnel in plaintext (2b04), 3/3 from a sensor
  not running a patched session. Run 1's A opened a session right after the driver had used the sensor.
- Without the setup patches, configs up to the 2625 B one are accepted, the 2666 B one returns no data and the
  2691 B one is rejected (5004).
- Run 4 (R A R E C A F G H): C then A (clean close, 1a, no reset) -> 2b04, so an unload does NOT leave a
  usable session behind (run 1's A stays unexplained). G (no 405 B patch) accepts every config incl. the
  2666 B (data returned) and 2691 / 3033 B ones: what the ROM lacks comes with the 2581 B patch.
- Hygiene (run 4): a 2b04 does not reset the sensor by itself (none within 20 s); the next access gets an I/O
  error and that resets it. Now forced right away. The first step after R timed out in init twice although
  the sensor was back after 1.2 s: steps now wait VFS495_PROBE_SETTLE (default 5 s) after a re-enumeration.
- Run 5 (R A R E F G H): with the 5 s wait, A and E still stopped at init, at the 4 KiB flash read (1f05) on a
  freshly reset sensor; every init with the 693 B patch reads it. G (no 405 B patch) and H (no 1301 B reload)
  both captured a full swipe (8283 / 4647 lines; data only, not decoded). F: I/O error uploading the 405 B
  patch, right after a reset (H uploads the same patch at the same point without a reset before it).
- Run 8 (R F R G R H R G, 3 swipes, traced): F fails after the 2666 B config's data read times out (no 2581 B
  patch), at the next patch write; not a 405 B problem. Without the 405 B patch finger detection is unreliable
  (7/13 over runs 5-8) and prints match worse (G vs G 0/6 >= 40, H vs H 21/56). All four patches stay.
- Run 7 (R F R H R G, 5 swipes each): F failed again (not an order effect); H 5/5 prints; G never saw the
  finger in 5 swipes although the user swiped (runs 5 and 6 found it).
- Run 6 (R A R E R F R H R G, prints decoded): without the 693 B patch on a fresh sensor, 1f05 is rejected
  (6d04), the handshake refused with 2604, and the 1301 B upload kills the sensor (E). F failed the same way
  again (both times right after a failed E); H and G (no 405 B) gave 200x300 prints.

T7 (405 B patch, what it changes): VFS495_PROBE_DUMP=DIR saves everything the sensor returns per step (setup
replies incl. extra bytes, ep 0x82 reads with the config's type-6 key, finger polls, the encrypted swipe and its
key) as dump-<step>-<time>.json, 0600; compare G against H with tools/compare_probe_dumps.py. E.g.
    sudo VFS495_PROBE_DUMP=/tmp/vfs-dump VFS495_PROBE_SWIPES=3 python3 probe_patches.py R G R H R G R H
T7 (2581 B patch / bare ROM): R U R V R W, and R P (the arming key is set via the type-6 block, wherever a
stripped config moves it).

02 configs are TLV lists after a 5 B header: u16le type, u16le length, payload (type 3 = 32-bit register write,
type 6 = image key + IV, ...). T drops whole TLVs and leaves everything else as recorded. Still RAM only.

Each variant reports how far it gets: flash read (RSA key), handshake (or the sensor's refusal), every setup
command's status and ep 0x82 read sizes, and whether a swipe after arming gives a print (swipe when asked,
within 15 s). The arming command gets a fresh image key, like the driver; the swipe is decrypted, checked for
valid frames and assembled. VFS495_PROBE_SWIPES=N re-arms for N swipes (setup again, fresh key each, like
the driver). VFS495_PROBE_OUT=DIR saves the prints there (0600, owned by the sudo user; never into the repo).

Debugging: each setup reply shows extra bytes after the status (`06(405):0000+32`); "polls" summarizes the
finger-state replies after arming (distinct reply, count, first seen); the swipe stream is read even when no
finger bit came, to see whether the sensor streams anyway; "failed at" says whether a command's write or its
reply failed and how long after the write. VFS495_PROBE_TRACE=DIR writes a per-step JSON trace (time, command,
reply length and first bytes; no patch or config bodies), 0600, owned by the sudo user.

Safety: only commands from the recorded setup, fewer of them, or (T) with TLVs removed. Patches and config live
in sensor RAM; nothing is written to flash. A refused or broken session makes the sensor reset itself (USB
re-enumeration), which clears it.
"""
import collections
import json
import os
import secrets
import struct
import sys
import time

import usb.core

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ssl_session as S  # noqa: E402
import vfs495_native_capture as N  # noqa: E402

FINGER_WAIT = 15
RESET_GONE_WAIT = 5          # an alert reset comes within ~0.2 s; a 2b04 refusal resets nothing by itself
RESET_BACK_WAIT = 20
SETTLE = float(os.environ.get("VFS495_PROBE_SETTLE", "5"))   # 1 s after re-enumeration was too short (run 4)
DEFAULT = "R F R G R H R G".split()
FLASH = None                 # 4 KiB flash block of the last init that read it (the RSA key is stable per device)
VARIANTS = "ABCDEFGHTUVWPM"
ROM_LACKS = {2666: (19, 20, 29, 7), 2691: (23, 27), 3033: (23, 27)}   # TLV types only the 2581 B patch accepts
DUMP = None                  # VFS495_PROBE_DUMP: everything the sensor returns in one variant run (see dump_*)
STRIP_TYPES = (23, 27)


def tlvs(cfg):
    """Split an 02 config into (header, [(type, payload)]). Raises if the TLVs don't end exactly."""
    out, o = [], 5
    while o < len(cfg):
        t, n = struct.unpack_from("<HH", cfg, o)
        if o + 4 + n > len(cfg):
            raise ValueError("TLV at %d overruns the config" % o)
        out.append((t, cfg[o + 4:o + 4 + n]))
        o += 4 + n
    return cfg[:5], out


def key6(cfg):
    """(key, iv) of a config's type-6 stream crypto block (its first 48 B), or None."""
    for t, p in tlvs(cfg)[1]:
        if t == 6:
            return p[:32], p[32:48]
    return None


def set_key6(cfg, key, iv):
    """The config with its type-6 block's key + IV replaced (offset 2927 / 2959 in the recorded 3033 B one)."""
    o = 5
    while o < len(cfg):
        t, n = struct.unpack_from("<HH", cfg, o)
        if t == 6:
            return cfg[:o + 4] + key + iv + cfg[o + 4 + 48:]
        o += 4 + n
    raise ValueError("config has no type-6 block")


def strip_rom_lacks(setup, extra=()):
    """Configs without the TLV types the ROM lacks (ROM_LACKS); extra = (size, types) pairs stripped too."""
    out = []
    for c, r in setup:
        if c[:1] == b"\x02":
            types = ROM_LACKS.get(len(c), ()) + tuple(t for n, ts in extra if n == len(c) for t in ts)
            if types:
                c = strip_tlvs(c, types)
        out.append((c, r))
    return out


class Plain:
    """Stands in for the SSL state in step P: commands go out and come back in plaintext."""
    def encrypt_record(self, typ, c):
        return c

    def decrypt_record(self, typ, body):
        return body, True


def strip_tlvs(cfg, types):
    hdr, items = tlvs(cfg)
    return hdr + b"".join(struct.pack("<HH", t, len(p)) + p for t, p in items if t not in types)


def drop_patches(setup, sizes):
    """Setup without the 06 patches of these sizes and the 1a unload right before each of them."""
    out = []
    for c, r in setup:
        if c[:1] == b"\x06" and len(c) in sizes:
            if out and out[-1][0] == b"\x1a":
                out.pop()
            continue
        out.append((c, r))
    return out


def drop_reload(setup):
    """Setup without the 1301 B patch's reload (and its 1a)."""
    return drop_patches(setup, (1301,))


def variant_cmds(init, setup, which):
    """(init, setup) for a variant. Setup entries stay (cmd, reads)."""
    no_setup_patches = [(c, r) for c, r in setup if c[:1] not in (b"\x06", b"\x1a")]
    keep = {"A": (), "B": (693,), "C": (693, 1301), "D": (), "E": (1301,),
            "F": (693, 1301), "G": (693, 1301), "H": (693, 1301), "T": (693, 1301),
            "U": (693, 1301), "V": (693, 1301), "W": (693, 1301), "P": (), "M": (693, 1301)}[which]
    init_v = [c for c in init if c[:1] != b"\x06" or len(c) in keep]
    if which == "P":                  # no session, so no RSA key needed: no flash reads (rejected without 693 B)
        init_v = [c for c in init_v if c[:1] != b"\x1f"]
    if which == "D":
        setup_v = list(setup)
    elif which == "F":
        setup_v = drop_patches(setup, (2581,))
    elif which == "G":
        setup_v = drop_patches(setup, (405,))
    elif which == "H":
        setup_v = drop_reload(setup)
    elif which == "T":
        setup_v = [(strip_tlvs(c, STRIP_TYPES) if c[:1] == b"\x02" and len(c) in (2691, 3033) else c, r)
                   for c, r in no_setup_patches]
    elif which in "UVW":
        setup_v = drop_patches(setup, (2581,))
        if which == "V":
            setup_v = [(c, r) for c, r in setup_v if not (c[:1] == b"\x02" and len(c) == 2666)]
        setup_v = strip_rom_lacks(setup_v, ((3033, (24,)),) if which == "W" else ())
    elif which == "M":
        setup_v = strip_rom_lacks([(c, r) for c, r in no_setup_patches if not (c[:1] == b"\x02" and len(c) == 2666)])
    elif which == "P":
        setup_v = strip_rom_lacks([(c, r) for c, r in no_setup_patches if c[:1] != b"\x1f"])
    else:
        setup_v = no_setup_patches
    return init_v, setup_v


def describe(cmds):
    return " ".join("%02x%s" % (c[0], "(%d)" % len(c) if c[0] in (2, 6) else "") for c in cmds)


def find_dev():
    return usb.core.find(idVendor=S.VID, idProduct=S.PID)


def wait_reset(old_addr, label):
    """Wait for a reset the sensor announced (refusal, alert, I/O error): first gone or re-addressed, then back.
    Returns a short description for the report."""
    t0 = time.monotonic()
    while time.monotonic() - t0 < RESET_GONE_WAIT:
        d = find_dev()
        if d is None or d.address != old_addr:
            break
        time.sleep(0.2)
    else:
        return None
    gone = time.monotonic() - t0
    t1 = time.monotonic()
    while time.monotonic() - t1 < RESET_BACK_WAIT:
        d = find_dev()
        if d is not None and d.address != old_addr:
            time.sleep(SETTLE)
            return "%s: reset after %.1f s, back after %.1f s more" % (label, gone, time.monotonic() - t1)
        time.sleep(0.2)
    return "%s: gone after %.1f s, NOT back within %d s" % (label, gone, RESET_BACK_WAIT)


def ensure_present():
    """Before a step: the sensor must be enumerated. Waits out a reset still in progress."""
    t0 = time.monotonic()
    while find_dev() is None:
        if time.monotonic() - t0 > RESET_BACK_WAIT:
            sys.exit("VFS495 not present after %d s; replug or reboot" % RESET_BACK_WAIT)
        time.sleep(0.2)
    if time.monotonic() - t0 > 0.1:
        time.sleep(SETTLE)


def status(reply):
    return reply[:2].hex() if len(reply) >= 2 else "short:" + reply.hex()


def last_cmd():
    out = [h for d, h, _ in S.TRAFFIC if d == "OUT"]
    return "%s (%d B)" % (out[-1][:8], len(out[-1]) // 2) if out else "none"


TRACE = []                   # (s since step start, what, detail) for VFS495_PROBE_TRACE
T0 = 0.0


def trace(what, detail):
    TRACE.append((round(time.monotonic() - T0, 4), what, detail))


def cmd_name(c):
    return "%02x%s" % (c[0], "(%d)" % len(c) if c[0] in (2, 6) else "")


def pcmd(dev, st, c, res):
    """S.command, but records which half failed (write or reply), how long after the write, and a trace line."""
    name = cmd_name(c)
    t0 = time.monotonic()
    try:
        S.send(dev, st.encrypt_record(0x17, c))
    except usb.core.USBError as e:
        res["failed at"] = "%s: write failed after %.3f s (%s)" % (name, time.monotonic() - t0, e)
        trace("write FAILED", name)
        raise
    try:
        raw = S.recv(dev, 0x4000, 3000)
    except usb.core.USBError as e:
        res["failed at"] = "%s: written, no reply after %.3f s (%s)" % (name, time.monotonic() - t0, e)
        trace("reply FAILED", name)
        raise
    out = raw if isinstance(st, Plain) else b""
    for typ, body in ([] if isinstance(st, Plain) else S.split_records(raw)):
        if typ == 0x15 and len(body) % 16:            # plaintext alert: the sensor dropped the session
            res["failed at"] = "%s: plaintext alert %s" % (name, body.hex())
            raise RuntimeError("sensor alert " + body.hex())
        data, ok = st.decrypt_record(typ, body)
        if not ok:
            raise RuntimeError("bad MAC on reply")
        out += data
    trace(name, "reply %d B %s after %.3f s" % (len(out), out[:8].hex(), time.monotonic() - t0))
    return out


class RecordingDev:
    """Forwards to the USB device and keeps every chunk read from ep 0x82 (for the swipe dump)."""
    def __init__(self, dev):
        self.dev, self.chunks = dev, []

    def read(self, ep, n, to):
        r = self.dev.read(ep, n, to)
        if ep == S.EP_DATA_IN:
            self.chunks.append(bytes(r))
        return r

    def __getattr__(self, name):
        return getattr(self.dev, name)


def dump_new(which):
    return {"variant": which, "time": int(time.time()), "setup": [], "polls": [], "swipes": []}


def dump_save(res):
    """Write the step's dump: JSON, bytes as hex. Raw sensor output incl. the swipe (biometric data): 0600."""
    out = os.environ.get("VFS495_PROBE_DUMP")
    if not out or DUMP is None:
        return
    path = os.path.join(out, "dump-%s-%d.json" % (DUMP["variant"], DUMP["time"]))
    save_private(path, json.dumps(DUMP).encode())
    res["dump"] = path


def save_private(path, data):
    """Write 0600, owned by the user who ran sudo (so they can read it without root)."""
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as f:
        f.write(data)
    if os.environ.get("SUDO_UID"):
        os.chown(path, int(os.environ["SUDO_UID"]), int(os.environ.get("SUDO_GID", "-1")))


def init_tolerant(dev, init, res):
    """S.init_sensor, but a timed-out flash data read is noted and init goes on (run 5: without the 693 B patch
    the 4 KiB read timed out on a freshly reset sensor). Returns this init's flash block, or b"" if none."""
    global FLASH
    flash = b""
    for c in init:
        time.sleep(S.INIT_PAUSE)
        S.send(dev, c)
        try:
            r = S.recv(dev)
        except usb.core.USBTimeoutError:
            res["init stop"] = "no reply to %02x (%d B)" % (c[0], len(c))
            raise
        trace("init " + cmd_name(c), "reply %d B %s" % (len(r), r[:8].hex()))
        if r[:1] == b"\x15":
            raise S.StaleSession()
        if c == b"\x01" and len(r) > 17 and r[17] and not flash:
            time.sleep(S.INIT_PAUSE)                     # patches still loaded: unload first, like HP
            S.send(dev, b"\x1a")
            S.recv(dev)
        if c[0] == 0x1F:
            size = struct.unpack_from("<I", c, 5)[0]
            try:
                data = S.recv(dev, size, 1000, S.EP_DATA_IN)
            except usb.core.USBTimeoutError:
                res["flash read"] = "%d B data read TIMED OUT (command reply %s)" % (size, status(r))
                continue
            if size == 0x1000:
                flash = data
    if flash:
        FLASH = flash
    return flash


def force_reset(init):
    """Step R: leave a stale session behind and poke it, so the sensor resets itself (see FINDINGS)."""
    res = {"step": "R"}
    dev = S.open_device()
    addr = dev.address
    try:
        try:
            modulus = S.flash_storage(init_tolerant(dev, init, res), 10)
            if modulus is None:
                raise RuntimeError("no RSA key from flash")
            S.handshake(dev, modulus)
            res["session"] = "opened, dropped without close_notify"
        except S.StaleSession:
            res["session"] = "sensor already held a stale session"
        except (RuntimeError, usb.core.USBError) as e:
            res["session"] = "no session (%s); the refusal resets it too" % e
        try:
            time.sleep(S.INIT_PAUSE)
            S.send(dev, b"\x01")
            r = S.recv(dev, 0x400, 1000)
            res["poke"] = "plaintext 01 -> %s" % (r[:5].hex())
        except usb.core.USBError as e:
            res["poke"] = "plaintext 01 -> %s" % e
    finally:
        S.close_device(dev)
    res["reset"] = wait_reset(addr, "R") or "NO reset within %d s" % RESET_GONE_WAIT
    return res


def plain_frames(chunks):
    """01fe frames in the stream as read, without decryption (does the sensor stream in plaintext?)."""
    data = b"".join(chunks)
    return sum(data[o:o + 2] == b"\x01\xfe" for o in range(0, len(data) - N.FRAME + 1, N.FRAME))


def plain_stop(dev):
    """stop_stream for step P: 04 in plaintext, drain, read the reply."""
    S.send(dev, b"\x04")
    try:
        while True:
            dev.read(S.EP_DATA_IN, 16384, 300)
    except usb.core.USBError:
        pass
    try:
        S.recv(dev, 0x400, 1000)
    except usb.core.USBError:
        pass


def run_setup(dev, st, which, setup_v, res):
    """GetVersion, then setup + arming + finger poll + swipe, VFS495_PROBE_SWIPES times. st: SSL state or Plain."""
    v = pcmd(dev, st, b"\x01", res)
    res["getversion"] = status(v) + (" patch byte %02x" % v[17] if len(v) > 17 else "")
    swipes = int(os.environ.get("VFS495_PROBE_SWIPES", "1"))
    images, prev = [], None
    arm = max(i for i, (c, _) in enumerate(setup_v) if c[:1] == b"\x02")     # the last config arms the sensor
    for k in range(swipes):
        tag = "" if swipes == 1 else " %d" % (k + 1)
        statuses = []
        key, iv = secrets.token_bytes(32), secrets.token_bytes(16)   # fresh image key per swipe, like the driver
        for i, (c, reads) in enumerate(setup_v):
            if i == arm:                          # via the type-6 block: a stripped config moves the key (T, U..W, P)
                c = set_key6(c, key, iv)
            r = pcmd(dev, st, c, res)
            data = []
            for n in reads:
                try:
                    data.append(S.recv(dev, n, 3000, S.EP_DATA_IN))
                except usb.core.USBError:
                    data.append(b"")
            got = [len(d) for d in data]
            if DUMP is not None:
                k6 = key6(c) if c[:1] == b"\x02" else None
                DUMP["setup"].append({"swipe": k + 1, "cmd": cmd_name(c), "reply": r.hex(),
                                      "reads": [len(d) if c[:1] == b"\x1f" else d.hex() for d in data],
                                      "key6": k6[0].hex() if k6 else None, "iv6": k6[1].hex() if k6 else None})
            ok = r[:2] == b"\x00\x00"
            name = cmd_name(c)
            extra = "+%d" % (len(r) - 2) if len(r) > 2 else ""      # e.g. a patch reply with 32 B after it
            statuses.append("%s:%s%s%s" % (name, status(r), extra,
                                           "" if got == reads else " reads %d/%d B" % (sum(got), sum(reads))))
            if not ok:
                res["setup" + tag] = " ".join(statuses)
                res["result"] = "setup command %s rejected: %s (reply %s)" % (name, status(r), r[:16].hex())
                res["_watch"] = True   # run 1 saw a reset after a rejection: don't start the next step into it
                return res
        if statuses != prev:                      # later swipes: only show the setup if it changed
            res["setup" + tag] = " ".join(statuses)
        prev = statuses
        # armed (the last setup command is the arming one): look for a finger, then for image data
        print("  [%s] armed: swipe your finger now (%d s)%s..." % (which, FINGER_WAIT, tag), flush=True)
        t_arm = time.monotonic()
        deadline, finger = t_arm + FINGER_WAIT, False
        polls = collections.OrderedDict()                   # reply -> [count, first seen (s after arming)]
        while time.monotonic() < deadline:
            f = pcmd(dev, st, b"\x17", res)
            if DUMP is not None:
                DUMP["polls"].append({"swipe": k + 1, "t": round(time.monotonic() - t_arm, 3), "reply": f.hex()})
            p = polls.setdefault(f[:8].hex(), [0, time.monotonic() - t_arm])
            p[0] += 1
            if len(f) > 2 and f[2] & 0x02:
                finger = True
                break
            time.sleep(0.05)
        res["polls" + tag] = ", ".join("%s x%d (from %.1f s)" % (h, n, t0) for h, (n, t0) in polls.items())
        perm = N.descramble_table()
        # read the stream even without a finger bit: does the sensor stream anyway?
        rdev = RecordingDev(dev)
        raw = N.read_swipe(rdev, key, iv, perm)             # decrypts; keeps only valid 01fe frames
        if DUMP is not None:                               # the encrypted stream as read, + its key
            DUMP["swipes"].append({"swipe": k + 1, "finger": finger, "key": key.hex(), "iv": iv.hex(),
                                   "chunks": [ch.hex() for ch in rdev.chunks]})
        if isinstance(st, Plain):
            plain_stop(dev)
        else:
            N.stop_stream(dev, st)                          # 04 abort, drain, resync
        streamed = sum(len(ch) for ch in rdev.chunks)
        trace("swipe", "finger bit %s, %d lines" % (finger, len(raw)))
        if len(raw) < N.MIN_LINES:
            res["swipe" + tag] = "%d decrypted lines (%d B streamed, %d plaintext 01fe frames): %s" % (
                len(raw), streamed, plain_frames(rdev.chunks),
                "too few" if finger else "no finger bit" + (", but it streamed" if streamed else ""))
            continue
        img = N.to_image(raw, perm)
        res["swipe" + tag] = "%d decrypted lines, image %dx%d%s" % (
            len(raw), img.shape[1], img.shape[0], "" if finger else " (finger bit NEVER set)")
        if img.shape[0] >= 80:
            images.append(img)
        out = os.environ.get("VFS495_PROBE_OUT")      # a fingerprint: keep it out of the repo, 0600
        if out:
            path = os.path.join(out, "probe-%s-%d-%d.pgm" % (which, int(time.time()), k + 1))
            save_private(path, b"P5\n%d %d\n255\n" % (img.shape[1], img.shape[0]) + img.tobytes())
            res["swipe" + tag] += " -> " + path
    res["result"] = ("CAPTURE WORKS (%d/%d prints)" % (len(images), swipes) if images
                     else "armed, but no print")
    return res


def run_variant(which, init, setup):
    global T0, DUMP
    res = {"variant": which}
    init_v, setup_v = variant_cmds(init, setup, which)
    S.TRAFFIC.clear()
    TRACE.clear()
    T0 = time.monotonic()
    DUMP = dump_new(which) if os.environ.get("VFS495_PROBE_DUMP") else None
    res["init"] = describe(init_v)
    dev = S.open_device()
    addr = dev.address
    res["usb address"] = addr
    st = None
    broken = watch = False
    try:
        # patch state before init: the first plaintext GetVersion reply
        n0 = len(S.TRAFFIC)
        try:
            flash = init_tolerant(dev, init_v, res)
        except S.StaleSession:
            res["result"] = "stale session from an earlier process (sensor resets); rerun"
            broken = True
            return res
        if which == "P":
            return run_setup(dev, Plain(), which, setup_v, res)
        t = S.TRAFFIC[n0:]
        vers = [bytes.fromhex(t[i + 1][1]) for i, (d, h, _) in enumerate(t[:-1]) if d == "OUT" and h == "01"]
        vers = [v for v in vers if len(v) > 17]
        if vers:
            res["patch byte"] = "%02x before init, %02x after" % (vers[0][17], vers[-1][17])
        if flash:
            res["flash"] = "ok (%d B)" % len(flash)
        elif FLASH:
            res["flash"] = "NO flash block; using the RSA key from an earlier step"
        else:
            res["flash"] = "NO flash block"
        modulus = S.flash_storage(flash or FLASH or b"", 10)
        if modulus is None:
            res["result"] = "stopped: no RSA key from flash"
            return res
        try:
            st = S.handshake(dev, modulus)
        except RuntimeError as e:
            res["handshake"] = "FAILED: %s" % e
            res["result"] = "no session"
            broken = True
            return res
        res["handshake"] = "ok"
        return run_setup(dev, st, which, setup_v, res)
    except (usb.core.USBError, RuntimeError) as e:
        res["result"] = "error: %s, last command sent %s" % (e, last_cmd())
        broken = True
        return res
    finally:
        if st is not None and not broken and not isinstance(st, Plain):
            res["close"] = "confirmed" if S.close_session(dev, st) else "NOT confirmed"
            broken = res["close"] != "confirmed"
        S.close_device(dev)
        out = os.environ.get("VFS495_PROBE_TRACE")
        if out and TRACE:
            path = os.path.join(out, "trace-%s-%d.json" % (which, int(time.time())))
            save_private(path, json.dumps(TRACE, indent=0).encode())
            res["trace"] = path
        dump_save(res)
        if broken or watch or res.pop("_watch", False):
            res["reset"] = wait_reset(addr, which) or "none within %d s" % RESET_GONE_WAIT
        if broken and res["reset"].startswith("none"):
            # after a 2b04 the sensor stays broken until the next access (run 4): reset it now
            res["recover"] = force_reset(init)["reset"]


def plan(steps, init, setup):
    for w in steps:
        if w == "R":
            print("R  init (as recorded): %s; handshake, drop it, plaintext 01 -> sensor resets" % describe(init))
            continue
        init_v, setup_v = variant_cmds(init, setup, w)
        print("%s  init:  %s" % (w, describe(init_v)))
        print("   setup: %s" % describe([c for c, _ in setup_v]))
        if w == "T":
            for c, _ in setup_v:
                if c[:1] == b"\x02" and any(t in STRIP_TYPES for t, _ in tlvs(c)[1]):
                    sys.exit("T: TLV strip failed")
            print("   (2691/3033 B configs without TLV types %s)" % ", ".join(map(str, STRIP_TYPES)))
        if w in "UVWPM":
            for c, _ in setup_v:
                if c[:1] == b"\x02" and any(t in (7, 19, 20, 29, 23, 27) + ((24,) if w == "W" else ())
                                              for t, _ in tlvs(c)[1]):
                    sys.exit("%s: TLV strip failed" % w)
            print("   (configs without the TLV types only the 2581 B patch accepts: %s%s)" % (
                "; ".join("%d B: %s" % (n, "/".join(map(str, ts))) for n, ts in ROM_LACKS.items()),
                "; 3033 B also 24" if w == "W" else ""))
        if w == "P":
            print("   (no session: every command in plaintext, no flash read, no handshake)")


def main():
    args = sys.argv[1:]
    dry = "--plan" in args
    steps = [a.upper() for a in args if a != "--plan"] or DEFAULT
    if any(len(w) != 1 or w not in "R" + VARIANTS for w in steps):
        sys.exit(__doc__)
    init = [bytes.fromhex(h) for h in json.load(open(S.CAP + "/init_cmds.json"))]
    setup = [(bytes.fromhex(h), r) for h, r in json.load(open(S.CAP + "/capture_cmds.json"))]
    for c, _ in setup:
        if c[:1] == b"\x02":
            tlvs(c)                    # every config must parse as TLVs (checks the capture and the parser)
    if dry:
        plan(steps, init, setup)
        return
    for w in steps:
        ensure_present()
        print("step %s ..." % w, flush=True)
        res = force_reset(init) if w == "R" else run_variant(w, init, setup)
        for k, v in res.items():
            print("  %-12s %s" % (k, v))


if __name__ == "__main__":
    main()
