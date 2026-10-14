#!/usr/bin/env python3
"""Verify local-backup media exactly as RestoreLocalAttachmentJob would: locate files/<xx>/<mediaName>,
check HMAC-SHA256, AES-CBC decrypt, take the first `size` bytes, compare SHA-256 with plaintextHash.
Usage: verify_media.py FRAMES_JSON FILES_DIR [--limit N] [--only-new MANIFEST]. Prints counts only."""
import argparse
import base64
import collections
import hashlib
import hmac
import json
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def pointers(o):
    if isinstance(o, dict):
        li = o.get("locatorInfo")
        if isinstance(li, dict) and li.get("localKey") and li.get("plaintextHash"):
            yield li
        for v in o.values():
            yield from pointers(v)
    elif isinstance(o, list):
        for v in o:
            yield from pointers(v)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("frames")
    ap.add_argument("files")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--only-new")
    a = ap.parse_args()
    only = set(open(a.only_new).read().split()) if a.only_new else None
    res = collections.Counter()
    done = set()
    for li in pointers(json.load(open(a.frames))):
        lk, ph, size = base64.b64decode(li["localKey"]), base64.b64decode(li["plaintextHash"]), int(li["size"])
        name = hashlib.sha256(ph + lk).hexdigest()
        if name in done or (only is not None and name not in only):
            continue
        done.add(name)
        p = os.path.join(a.files, name[:2], name)
        if not os.path.exists(p):
            res["file missing"] += 1
            continue
        blob = open(p, "rb").read()
        iv, ct, mac = blob[:16], blob[16:-32], blob[-32:]
        if not hmac.compare_digest(hmac.new(lk[32:], iv + ct, hashlib.sha256).digest(), mac):
            res["bad MAC"] += 1
            continue
        pt = Cipher(algorithms.AES(lk[:32]), modes.CBC(iv)).decryptor().update(ct)[:size]
        res["OK" if hashlib.sha256(pt).digest() == ph else "hash mismatch"] += 1
        if a.limit and len(done) >= a.limit:
            break
    print(dict(res))


if __name__ == "__main__":
    main()
