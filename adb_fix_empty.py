#!/usr/bin/env python3
"""Work around a signalbackup-tools adb-import bug: a message whose encrypted body decrypts to an EMPTY
string is treated as a decryption failure and dropped together with its attachments.

Usage: adb_fix_empty.py ADBDIR [--passfile FILE]   (ADBDIR = scratch copy with db/ and sp/)
Derives the master secret exactly as AdbBackupDatabase does (PKCS#12/SHA-1 from the app passphrase,
or "unencrypted" when none), decrypts every mms/sms body, and sets body = NULL where the plaintext is
empty. Prints counts only. Operates on db/messages.db inside ADBDIR (must be a Linux-side copy).
"""
import argparse
import base64
import hashlib
import hmac
import re
import sqlite3
import sys

from cryptography.hazmat.primitives import padding as sympad
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def pkcs12_kdf(password, salt, ident, iterations, n):
    """RFC 7292 appendix B.2 with SHA-1 (as OpenSSL PKCS12_key_gen_utf8)."""
    u, v = 20, 64
    pw = (password.encode("utf-16-be") + b"\0\0") if password is not None else b""
    D = bytes([ident]) * v
    S = (salt * ((v * ((len(salt) + v - 1) // v)) // len(salt) + 1))[: v * ((len(salt) + v - 1) // v)] if salt else b""
    P = (pw * ((v * ((len(pw) + v - 1) // v)) // len(pw) + 1))[: v * ((len(pw) + v - 1) // v)] if pw else b""
    I = bytearray(S + P)
    out = b""
    while len(out) < n:
        A = hashlib.sha1(D + bytes(I)).digest()
        for _ in range(iterations - 1):
            A = hashlib.sha1(A).digest()
        out += A
        B = (A * (v // u + 1))[:v]
        Bn = int.from_bytes(B, "big")
        for j in range(0, len(I), v):
            Ij = int.from_bytes(I[j:j + v], "big")
            Ij = (Ij + Bn + 1) % (1 << (8 * v))
            I[j:j + v] = Ij.to_bytes(v, "big")
    return out[:n]


def pref(xml, kind, name):
    m = re.search(rf'<{kind} name="{re.escape(name)}"(?: value="([^"]*)")?\s*/?>([^<]*)', xml)
    if not m:
        return None
    return m.group(1) if m.group(1) is not None else m.group(2)


def aes_cbc_decrypt(key, iv, ct):
    d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor().update(ct)
    u = sympad.PKCS7(128).unpadder()
    return u.update(d) + u.finalize()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("adbdir")
    ap.add_argument("--passfile")
    a = ap.parse_args()
    passphrase = open(a.passfile).read().rstrip("\r\n") if a.passfile else "unencrypted"

    xml = open(f"{a.adbdir}/sp/SecureSMS-Preferences.xml", encoding="utf-8").read()
    iterations = int(pref(xml, "int", "passphrase_iterations") or 100)
    mac_salt = base64.b64decode(pref(xml, "string", "mac_salt"))
    enc_salt = base64.b64decode(pref(xml, "string", "encryption_salt"))
    ms = base64.b64decode(pref(xml, "string", "master_secret"))

    kek_mac = pkcs12_kdf(passphrase, mac_salt, 1, iterations, 16)
    if not hmac.compare_digest(hmac.new(kek_mac, ms[:-20], hashlib.sha1).digest(), ms[-20:]):
        print("master secret HMAC check FAILED (wrong app passphrase?)")
        sys.exit(1)
    ck = pkcs12_kdf(passphrase, enc_salt, 1, iterations, 16)
    iv = pkcs12_kdf(passphrase, enc_salt, 2, iterations, 16)
    combined = aes_cbc_decrypt(ck, iv, ms[:-20])
    enc_key, mac_key = combined[:16], combined[16:36]

    db = sqlite3.connect(f"{a.adbdir}/db/messages.db")
    stats = {}
    for tab in ("sms", "mms"):
        ok = empty = bad = 0
        clear = []
        for rid, body in db.execute(f"SELECT _id, body FROM {tab} WHERE body IS NOT NULL AND body != ''"):
            try:
                raw = base64.b64decode(body)
                if not hmac.compare_digest(hmac.new(mac_key, raw[:-20], hashlib.sha1).digest(), raw[-20:]):
                    bad += 1
                    continue
                pt = aes_cbc_decrypt(enc_key, raw[:16], raw[16:-20])
            except Exception:
                bad += 1
                continue
            if pt:
                ok += 1
            else:
                empty += 1
                clear.append((rid,))
        db.executemany(f"UPDATE {tab} SET body = NULL WHERE _id = ?", clear)
        stats[tab] = (ok, empty, bad)
    db.commit()
    for tab, (ok, empty, bad) in stats.items():
        print(f"{tab}: decrypt ok {ok}, empty (cleared) {empty}, undecryptable {bad}")


if __name__ == "__main__":
    main()
