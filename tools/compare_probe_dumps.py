#!/usr/bin/env python3
"""Compare what the VFS495 returns with and without a patch: dumps from probe_patches.py (VFS495_PROBE_DUMP).

    python3 compare_probe_dumps.py DUMP.json...      (no sensor, no root; group by variant, e.g. G vs H)

T7: what does the 405 B patch change? G runs setup without it, H with it (same session flow otherwise).
Reported per variant:
  replies   every setup command's reply after the status (e.g. 2402 B after a 2691 B config): length, whether
            it's the same in every run of the variant, and how much it differs between variants
  reads     the ep 0x82 data after each config: entropy, and for configs with a type-6 block (2331 B, 2691 B)
            the data decrypted with that block's key + IV (AES-256-CBC, one stream like the swipe); 01fe frames
            in it are counted and averaged per column. Reads of configs without a type-6 block are compared raw.
  polls     the finger-state replies after arming: the first one, the distinct ones, when the finger bit came
  swipe     the decrypted swipe: frame headers, per-column baseline (median over the quiet lines, i.e. no
            ridges), contrast (pixel spread on the strongest lines), line noise (quiet lines, line to line)
Then baseline / contrast profiles of the first two variants against each other.

The dumps hold raw sensor output incl. the swipe (biometric data): keep them out of the repo.
"""
import collections
import json
import sys

import numpy as np
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

FRAME, HDR, WIDTH, MAIN = 272, 8, 264, 200
QUIET_FRAC = 0.1


def descramble_table():
    import os
    import re
    here = os.path.dirname(os.path.abspath(__file__))
    src = open(here + "/../driver/vfs495_descramble.inc").read().split("{", 1)[1].split("}", 1)[0]
    perm = np.array([int(x) for x in re.findall(r"\b\d+\b", src)])
    assert sorted(perm) == list(range(WIDTH)), "bad descramble table"
    return perm


PERM = descramble_table()


def entropy(b):
    if not b:
        return 0.0
    c = np.bincount(np.frombuffer(b, np.uint8), minlength=256).astype(float)
    p = c[c > 0] / len(b)
    return float(-(p * np.log2(p)).sum()) + 0.0       # + 0.0: no "-0.00"


def decrypt(data, key, iv):
    n = len(data) - len(data) % 16
    return Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor().update(data[:n])


def frames(plain):
    """(headers, pixels) of the 01fe frames in a decrypted stream; pixels descrambled to (n, 264)."""
    hdrs, px = [], []
    for o in range(0, len(plain) - FRAME + 1, FRAME):
        f = plain[o:o + FRAME]
        if f[:2] == b"\x01\xfe":
            hdrs.append(f[:HDR])
            px.append(np.frombuffer(f[HDR:], np.uint8))
    if not px:
        return [], np.zeros((0, WIDTH), np.uint8)
    raw = np.array(px)
    out = np.zeros_like(raw)
    out[:, PERM] = raw
    return hdrs, out


def swipe_stats(img):
    """Per-column baseline / contrast / noise of a descrambled (n, 264) swipe."""
    main = img[:, :MAIN].astype(float)
    energy = np.abs(np.diff(main, axis=1)).mean(axis=1)
    quiet = energy <= max(QUIET_FRAC * energy.max(), np.percentile(energy, 10))   # at least the calmest 10 %
    strong = energy >= np.percentile(energy, 75)
    q = img[quiet].astype(float)
    return {
        "lines": len(img), "quiet": int(quiet.sum()),
        "baseline": np.median(q, axis=0),                         # per column, no ridges
        "contrast": img[strong].astype(float).std(axis=0),        # per column, ridges vs valleys
        "noise": np.diff(q, axis=0).std(axis=0) / np.sqrt(2) if len(q) > 2 else np.zeros(WIDTH),
        "mean": img.astype(float).mean(axis=0),
        "energy": float(np.median(energy[strong])),
    }


def fmt_prof(v):
    m, a = v[:MAIN], v[MAIN:]
    return "main %.1f (%.1f..%.1f)  aux %.1f (%.1f..%.1f)" % (m.mean(), m.min(), m.max(), a.mean(), a.min(), a.max())


def keyed(entries):
    """Setup entries of the first swipe, keyed (cmd, n-th occurrence) so variants with fewer commands line up."""
    seen, out = collections.Counter(), collections.OrderedDict()
    for e in entries:
        if e["swipe"] != 1:
            continue
        seen[e["cmd"]] += 1
        out[(e["cmd"], seen[e["cmd"]])] = e
    return out


def main():
    paths = sys.argv[1:]
    if not paths or paths[0] in ("-h", "--help"):
        sys.exit(__doc__)
    by_var = collections.OrderedDict()
    for p in paths:
        d = json.load(open(p))
        d["path"] = p
        by_var.setdefault(d["variant"], []).append(d)
    print("dumps: " + ", ".join("%s x%d" % (v, len(ds)) for v, ds in by_var.items()))

    # ---- setup replies and data reads -------------------------------------------------------
    keys = []
    for d in sorted((d for ds in by_var.values() for d in ds), key=lambda d: -len(keyed(d["setup"]))):
        if True:
            for k in keyed(d["setup"]):
                if k not in keys:
                    keys.append(k)
    print("\n== setup replies (after the 2 B status) and ep 0x82 reads, first swipe of each run ==")
    for k in keys:
        name = "%s #%d" % k
        rows = []
        for v, ds in by_var.items():
            es = [keyed(d["setup"]).get(k) for d in ds]
            es = [e for e in es if e]
            if not es:
                rows.append("  %s: (not sent)" % v)
                continue
            reps = [bytes.fromhex(e["reply"]) for e in es]
            st = sorted({r[:2].hex() for r in reps})
            extra = [r[2:] for r in reps]
            same = len({x for x in extra}) == 1
            line = "  %s: status %s, +%s B%s" % (v, "/".join(st), "/".join(sorted({str(len(x)) for x in extra})),
                                                "" if len(extra) < 2 else (" same in all runs" if same
                                                                           else " DIFFERS between runs"))
            rd = [b"".join(bytes.fromhex(x) for x in e["reads"] if isinstance(x, str)) for e in es]
            if any(rd):
                line += "; reads %s B, entropy %.2f" % ("/".join(str(len(x)) for x in rd), entropy(rd[0]))
                if es[0]["key6"]:
                    plain = [decrypt(r, bytes.fromhex(e["key6"]), bytes.fromhex(e["iv6"])) for r, e in zip(rd, es)]
                    h, img = frames(plain[0])
                    line += "; decrypted entropy %.2f, %d 01fe frames" % (entropy(plain[0]), len(h))
                    if len(h):
                        line += ", column mean " + fmt_prof(img.astype(float).mean(axis=0))
            rows.append(line)
        print(name)
        print("\n".join(rows))
        # between variants: the extra reply bytes and plaintext reads of the first run of each
        firsts = [(v, keyed(ds[0]["setup"]).get(k)) for v, ds in by_var.items()]
        firsts = [(v, e) for v, e in firsts if e]
        if len(firsts) >= 2:
            (va, ea), (vb, eb) = firsts[:2]
            for what, a, b in (("reply", bytes.fromhex(ea["reply"])[2:], bytes.fromhex(eb["reply"])[2:]),
                               ("reads", *(b"".join(bytes.fromhex(x) for x in e["reads"] if isinstance(x, str))
                                           for e in (ea, eb)))):
                if ea["key6"] and what == "reads":
                    continue                       # encrypted with different keys: compared via frames above
                if not a and not b:
                    continue
                n = min(len(a), len(b))
                if n == 0:
                    print("  %s vs %s %s: lengths %d / %d" % (va, vb, what, len(a), len(b)))
                    continue
                x, y = np.frombuffer(a[:n], np.uint8).astype(int), np.frombuffer(b[:n], np.uint8).astype(int)
                diff = np.nonzero(x != y)[0]
                print("  %s vs %s %s: %d / %d B differ, mean |diff| %.1f, mean %.1f vs %.1f%s" % (
                    va, vb, what, len(diff), n, np.abs(x - y).mean(), x.mean(), y.mean(),
                    "" if not len(diff) else ", first at %d" % diff[0]))

    # ---- finger polls -----------------------------------------------------------------------
    print("\n== finger polls after arming ==")
    for v, ds in by_var.items():
        for d in ds:
            for s in sorted({p["swipe"] for p in d["polls"]}):
                ps = [p for p in d["polls"] if p["swipe"] == s]
                cnt = collections.Counter(p["reply"] for p in ps)
                fin = [p["t"] for p in ps if len(p["reply"]) > 4 and int(p["reply"][4:6], 16) & 2]
                print("  %s %s swipe %d: first %s; %s; finger bit %s" % (
                    v, d["time"], s, ps[0]["reply"], ", ".join("%s x%d" % kv for kv in cnt.items()),
                    "at %.2f s" % fin[0] if fin else "never"))

    # ---- swipes -----------------------------------------------------------------------------
    print("\n== swipes (decrypted, descrambled) ==")
    agg = collections.OrderedDict()
    for v, ds in by_var.items():
        for d in ds:
            for s in d["swipes"]:
                data = b"".join(bytes.fromhex(c) for c in s["chunks"])
                h, img = frames(decrypt(data, bytes.fromhex(s["key"]), bytes.fromhex(s["iv"])))
                if len(img) < 20:
                    print("  %s %s swipe %d: %d frames, skipped" % (v, d["time"], s["swipe"], len(img)))
                    continue
                st = swipe_stats(img)
                hd = collections.Counter(x[2:].hex() for x in h)
                print("  %s %s swipe %d: %d lines (%d quiet), ridge energy %.1f, %d distinct headers (top %s)" % (
                    v, d["time"], s["swipe"], st["lines"], st["quiet"], st["energy"], len(hd),
                    ", ".join("%s x%d" % kv for kv in hd.most_common(3))))
                print("      baseline %s" % fmt_prof(st["baseline"]))
                print("      contrast %s" % fmt_prof(st["contrast"]))
                print("      noise    %s" % fmt_prof(st["noise"]))
                agg.setdefault(v, []).append(st)
    if len(agg) >= 2:
        (va, sa), (vb, sb) = list(agg.items())[:2]
        print("\n== %s vs %s, averaged over swipes (%d / %d) ==" % (va, vb, len(sa), len(sb)))
        for f in ("baseline", "contrast", "noise", "mean"):
            a = np.mean([s[f] for s in sa], axis=0)
            b = np.mean([s[f] for s in sb], axis=0)
            m = slice(0, MAIN)
            r = np.corrcoef(a[m], b[m])[0, 1] if a[m].std() > 0 and b[m].std() > 0 else float("nan")
            print("  %-8s %s: %s" % (f, va, fmt_prof(a)))
            print("  %-8s %s: %s" % ("", vb, fmt_prof(b)))
            print("  %-8s main: mean |diff| %.2f, ratio %.2f, column correlation %.2f" % (
                "", np.abs(a[m] - b[m]).mean(), a[m].mean() / max(b[m].mean(), 1e-9), r))
        print("  ridge energy %s %.1f vs %s %.1f" % (va, np.mean([s["energy"] for s in sa]),
                                                    vb, np.mean([s["energy"] for s in sb])))


if __name__ == "__main__":
    main()
