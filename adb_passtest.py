#!/usr/bin/env python3
"""Find the old Signal app passphrase for each adb dump among candidate lines.

Usage: adb_passtest.py CANDIDATES YEAR=ADBDIR [YEAR=ADBDIR ...]
Tries each line as-is (minus the newline) and trimmed, plus the built-in "unencrypted" default, against the
master_secret MAC in sp/SecureSMS-Preferences.xml. On a match writes $PASS_DIR/adb<YEAR>.pass (mode 600, default ./secrets).
Never prints a passphrase; prints the matching line number only.
"""
import base64
import hashlib
import hmac
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from adb_fix_empty import pkcs12_kdf, pref  # noqa: E402


def main():
    cand_path, targets = sys.argv[1], sys.argv[2:]
    lines = open(cand_path, encoding="utf-8").read().split("\n")
    tries = [("default 'unencrypted'", "unencrypted")]
    for i, line in enumerate(lines, 1):
        line = line.rstrip("\r")
        if line:
            tries.append((f"line {i}", line))
            if line.strip() != line:
                tries.append((f"line {i} (trimmed)", line.strip()))
    for t in targets:
        year, adbdir = t.split("=", 1)
        xml = open(f"{adbdir}/sp/SecureSMS-Preferences.xml", encoding="utf-8").read()
        it = int(pref(xml, "int", "passphrase_iterations") or 100)
        salt = base64.b64decode(pref(xml, "string", "mac_salt"))
        ms = base64.b64decode(pref(xml, "string", "master_secret"))
        hit = None
        for label, pw in tries:
            k = pkcs12_kdf(pw, salt, 1, it, 16)
            if hmac.compare_digest(hmac.new(k, ms[:-20], hashlib.sha1).digest(), ms[-20:]):
                hit = (label, pw)
                break
        if hit:
            pdir = os.environ.get("PASS_DIR", "secrets"); os.makedirs(pdir, mode=0o700, exist_ok=True)
            out = os.path.join(pdir, f"adb{year}.pass")
            fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(hit[1])
            print(f"{year}: MATCH ({hit[0]}) — saved")
        else:
            print(f"{year}: no match among {len(tries)} tries")


if __name__ == "__main__":
    main()
