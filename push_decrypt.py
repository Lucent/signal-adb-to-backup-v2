#!/usr/bin/env python3
"""Decrypt the never-processed envelopes in an old dump's `push` table with that dump's saved sessions.

Usage: push_decrypt.py ADBDIR PASSFILE OUT.json
Writes OUT.json = list of {source, device, envelope_ts, kind, body?, ts?, expire?, attachments:[...]} for the
caller (adb2v2.py) to turn into chat items. Prints counts only.
"""
import base64
import collections
import json
import os
import struct
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from adb2v2 import OldDump, canon_e164, unb64  # noqa: E402
from adb_fix_empty import pref  # noqa: E402

TOOL = os.environ.get("OLD_PUSH_DECRYPT", "old_push_decrypt")  # path to the built libsignal example (see README)


def fields(buf):
    i, out = 0, collections.defaultdict(list)
    while i < len(buf):
        key, i = varint(buf, i)
        num, wt = key >> 3, key & 7
        if wt == 0:
            v, i = varint(buf, i)
        elif wt == 1:
            v, i = buf[i:i + 8], i + 8
        elif wt == 2:
            n, i = varint(buf, i)
            v, i = buf[i:i + n], i + n
        elif wt == 5:
            v, i = buf[i:i + 4], i + 4
        else:
            raise ValueError("wire type")
        out[num].append(v)
    return out


def varint(b, i):
    s = v = 0
    while True:
        x = b[i]
        i += 1
        v |= (x & 0x7F) << s
        if not x & 0x80:
            return v, i
        s += 7


def strip_padding(pt):
    j = len(pt) - 1
    while j >= 0 and pt[j] == 0:
        j -= 1
    return pt[:j] if j >= 0 and pt[j] == 0x80 else pt


def parse_data_message(b):
    f = fields(b)
    msg = {"kind": "data"}
    if f.get(1):
        msg["body"] = f[1][0].decode("utf-8", "replace")
    if f.get(4):
        msg["flags"] = f[4][0]
    if f.get(5):
        msg["expire"] = f[5][0]
    if f.get(7):
        msg["ts"] = f[7][0]
    if f.get(3):
        msg["group"] = True
    atts = []
    for a in f.get(2, []):
        af = fields(a)
        att = {"cdn_id": struct.unpack("<Q", af[1][0])[0] if af.get(1) else None,
               "contentType": af[2][0].decode() if af.get(2) else None,
               "key": base64.b64encode(af[3][0]).decode() if af.get(3) else None,
               "size": af[4][0] if af.get(4) else None,
               "digest": base64.b64encode(af[6][0]).decode() if af.get(6) else None,
               "fileName": af[7][0].decode("utf-8", "replace") if af.get(7) else None,
               "width": af[9][0] if af.get(9) else None, "height": af[10][0] if af.get(10) else None}
        atts.append(att)
    msg["attachments"] = atts
    return msg


def main():
    root, passfile, out = sys.argv[1:4]
    sroot, spass = (sys.argv[4], sys.argv[5]) if len(sys.argv) > 5 else (root, passfile)
    d = OldDump("push", root, open(passfile, encoding="utf-8").read().rstrip("\r\n"), 0, 0)
    sd_ = OldDump("sess", sroot, open(spass, encoding="utf-8").read().rstrip("\r\n"), 0, 0) if sroot != root else d
    xml = open(f"{sroot}/sp/SecureSMS-Preferences.xml", encoding="utf-8").read()
    pub, priv = unb64(pref(xml, "string", "pref_identity_public_v3")), unb64(pref(xml, "string", "pref_identity_private_v3"))
    lines = [f"ID {pub.hex()} {priv.hex()}"]
    sessdir = f"{sroot}/f/sessions-v2"
    nsess = 0
    for fn in sorted(os.listdir(sessdir)) if os.path.isdir(sessdir) else []:
        stem, _, dev = fn.partition(".")
        if dev and not (dev.isdigit() and 0 < int(dev) < 256):
            continue
        name = sd_.canon.get(stem, stem)
        e = canon_e164(name)
        name = ("+" + e) if e else name.replace(" ", "")
        raw = open(os.path.join(sessdir, fn), "rb").read()
        ver = struct.unpack(">i", raw[:4])[0]
        n = struct.unpack(">i", raw[4:8])[0]
        blob = raw[8:8 + n]
        if ver < 3:
            blob = sd_.mc.decrypt(blob)
        lines.append(f"SESSION {name} {dev or 1} {blob.hex()}")
        nsess += 1
    rows = d.db.execute("SELECT _id, type, source, device_id, body, content, timestamp FROM push ORDER BY _id").fetchall()
    meta = {}
    for r in rows:
        for part, col in (("L", "body"), ("C", "content")):
            if r[col]:
                idx = f"{r['_id']}{part}"
                meta[idx] = r
                lines.append(f"MSG {idx} {'+' + canon_e164(r['source'])} {r['device_id'] or 1} {unb64(r[col]).hex()}")
    res = subprocess.run([TOOL], input="\n".join(lines) + "\n", capture_output=True, text=True)
    results, outcome = [], collections.Counter()
    for line in res.stdout.splitlines():
        st, idx, rest = line.split(" ", 2)
        r = meta[idx]
        if st == "ERR":
            outcome[f"error: {rest[:60]}"] += 1
            results.append({"source": r["source"], "device": r["device_id"], "envelope_ts": r["timestamp"], "kind": "undecryptable"})
            continue
        pt = strip_padding(bytes.fromhex(rest))
        try:
            if idx.endswith("L"):
                msg = parse_data_message(pt)
            else:
                c = fields(pt)
                if c.get(1):
                    msg = parse_data_message(c[1][0])
                elif c.get(5):
                    msg = {"kind": "receipt"}
                elif c.get(2):
                    msg = {"kind": "sync"}
                elif c.get(3):
                    msg = {"kind": "call"}
                elif c.get(4):
                    msg = {"kind": "null"}
                else:
                    msg = {"kind": "unknown-content"}
        except Exception:
            msg = {"kind": "unparseable"}
        msg.update(source=r["source"], device=r["device_id"], envelope_ts=r["timestamp"])
        results.append(msg)
        outcome[f"ok: {msg['kind']}" + (" with text" if msg.get("body") else "") + (f" +{len(msg['attachments'])} att" if msg.get("attachments") else "")] += 1
    json.dump(results, open(out, "w", encoding="utf-8"), ensure_ascii=False)
    print(f"sessions loaded: {nsess}; envelopes: {len(meta)}")
    if res.stderr.strip():
        print("tool notes:", len(res.stderr.strip().splitlines()), "line(s):", res.stderr.strip().splitlines()[0][:120])
    for k, v in outcome.most_common():
        print(f"  {k}: {v}")


if __name__ == "__main__":
    main()
