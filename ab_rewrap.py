#!/usr/bin/env python3
"""Turn old Signal/TextSecure .ab backups into plain tars that need no old secrets, verified losslessly.

Usage: ab_rewrap.py OUTDIR LABEL=FILE.ab [LABEL=FILE.ab ...]

For each .ab:
  1. asks for the Android backup password if the file is encrypted, then decrypts and decompresses to OUTDIR/LABEL.tar
  2. asks for the old Signal app passphrase (the previous one is tried first) and re-wraps the 36-byte master secret
     to Signal's built-in "unencrypted" passphrase (new salts, same scheme as MasterSecretUtil), and sets
     pref_disable_passphrase=true. Only these two settings files change; message data is untouched.
  3. verifies: every other tar member is byte-identical (same order, names, modes, times); the new wrap opens with the
     default passphrase and yields the identical master secret; every sms/mms body and every app_parts file decrypts.
Then protect OUTDIR/*.tar with one modern password (e.g. 7-Zip AES-256) and delete the plain tars.
Passwords are read with getpass and never printed or stored. Prints counts only.
"""
import base64
import copy
import getpass
import hashlib
import hmac
import io
import os
import re
import secrets
import sqlite3
import sys
import tarfile
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ab_check import StreamReader, payload_stream  # noqa: E402
from adb_fix_empty import pkcs12_kdf, pref  # noqa: E402

from cryptography.hazmat.primitives import padding as sympad
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

DEFAULT = "unencrypted"
PREFS = "sp/SecureSMS-Preferences.xml"
APPPREFS = "sp/org.thoughtcrime.securesms_preferences.xml"


def aes_cbc(key, iv, data, enc):
    c = Cipher(algorithms.AES(key), modes.CBC(iv))
    if enc:
        p = sympad.PKCS7(128).padder()
        return c.encryptor().update(p.update(data) + p.finalize())
    u = sympad.PKCS7(128).unpadder()
    return u.update(c.decryptor().update(data)) + u.finalize()


def unwrap(xml, pw):
    it = int(pref(xml, "int", "passphrase_iterations") or 100)
    mac_salt = base64.b64decode(pref(xml, "string", "mac_salt"))
    enc_salt = base64.b64decode(pref(xml, "string", "encryption_salt"))
    ms = base64.b64decode(pref(xml, "string", "master_secret"))
    if not hmac.compare_digest(hmac.new(pkcs12_kdf(pw, mac_salt, 1, it, 16), ms[:-20], hashlib.sha1).digest(), ms[-20:]):
        return None
    return aes_cbc(pkcs12_kdf(pw, enc_salt, 1, it, 16), pkcs12_kdf(pw, enc_salt, 2, it, 16), ms[:-20], False)


def wrap(xml, combined, pw):
    it = int(pref(xml, "int", "passphrase_iterations") or 100)
    enc_salt, mac_salt = secrets.token_bytes(16), secrets.token_bytes(16)
    ct = aes_cbc(pkcs12_kdf(pw, enc_salt, 1, it, 16), pkcs12_kdf(pw, enc_salt, 2, it, 16), combined, True)
    blob = ct + hmac.new(pkcs12_kdf(pw, mac_salt, 1, it, 16), ct, hashlib.sha1).digest()
    for name, val in (("encryption_salt", enc_salt), ("mac_salt", mac_salt), ("master_secret", blob)):
        xml, n = re.subn(rf'(<string name="{name}">)[^<]*(</string>)', lambda m: m.group(1) + base64.b64encode(val).decode() + m.group(2), xml)
        assert n == 1, name
    return xml


def set_disable(xml):
    if re.search(r'<boolean name="pref_disable_passphrase" value="[^"]*"', xml):
        return re.sub(r'(<boolean name="pref_disable_passphrase" value=")[^"]*(")', r"\1true\2", xml)
    return xml.replace("</map>", '    <boolean name="pref_disable_passphrase" value="true" />\n</map>', 1)


def master_cipher(combined):
    enc, mac = combined[:16], combined[16:36]

    def dec(raw):
        if not hmac.compare_digest(hmac.new(mac, raw[:-20], hashlib.sha1).digest(), raw[-20:]):
            raise ValueError("mac")
        return aes_cbc(enc, raw[:16], raw[16:-20], False)
    return dec


def process(outdir, label, path, pw_cache):
    print(f"== {label}")
    raw_tar = os.path.join(outdir, f"{label}.orig.tar")
    with open(path, "rb") as f, open(raw_tar, "wb") as out:
        header = [f.readline().rstrip(b"\n").decode() for _ in range(4)]
        assert header[0] == "ANDROID BACKUP"
        if header[3] == "AES-256":
            header += [f.readline().rstrip(b"\n").decode() for _ in range(5)]
        for chunk in payload_stream(f, header, int(header[1])):
            out.write(chunk)

    with tarfile.open(raw_tar, "r:") as t:
        members = t.getmembers()
        pm = next(m for m in members if m.name.endswith(PREFS))
        root = pm.name[: -len(PREFS)]
        am = next((m for m in members if m.name == root + APPPREFS), None)
        xml = t.extractfile(pm).read().decode("utf-8")
        axml = t.extractfile(am).read().decode("utf-8") if am else None

    combined = unwrap(xml, DEFAULT)
    if combined is not None:
        print("Signal app passphrase: none set; nothing to re-wrap")
    else:
        for pw in pw_cache:
            combined = unwrap(xml, pw)
            if combined is not None:
                print("Signal app passphrase: same as previous file")
                break
        while combined is None:
            pw = getpass.getpass("Old Signal app passphrase (hidden): ")
            combined = unwrap(xml, pw)
            print("Signal app passphrase:", "correct" if combined else "WRONG, try again")
            if combined:
                pw_cache.append(pw)
    new_xml = wrap(xml, combined, DEFAULT)
    assert unwrap(new_xml, DEFAULT) == combined
    new_axml = set_disable(axml) if axml is not None else None
    replace = {pm.name: new_xml.encode("utf-8")}
    if am is not None:
        replace[am.name] = new_axml.encode("utf-8")

    new_tar = os.path.join(outdir, f"{label}.tar")
    with tarfile.open(raw_tar, "r:") as src, tarfile.open(new_tar, "w:", format=src.format, pax_headers=src.pax_headers) as dst:
        for m in src:
            if m.name in replace:
                data = replace[m.name]
                m2 = copy.copy(m)
                m2.size = len(data)
                dst.addfile(m2, io.BytesIO(data))
            else:
                dst.addfile(m, src.extractfile(m) if m.isfile() else None)

    # ---- verification ----
    def digest(path):
        out = []
        with tarfile.open(path, "r:") as t:
            for m in t:
                h = hashlib.sha256(t.extractfile(m).read()).hexdigest() if m.isfile() else ""
                out.append((m.name, m.type, m.mode, m.mtime, m.uid, m.gid, h))
        return out
    a, b = digest(raw_tar), digest(new_tar)
    assert [x[0] for x in a] == [x[0] for x in b], "member list differs"
    changed = [x[0] for x, y in zip(a, b) if x != y]
    assert set(changed) <= set(replace), f"unexpected changes: {changed}"
    print(f"tar members: {len(b)}; identical: {len(b) - len(changed)}; changed (settings only): {len(changed)}")

    dec = master_cipher(unwrap(new_xml, DEFAULT))
    with tarfile.open(new_tar, "r:") as t, tempfile.TemporaryDirectory(dir=outdir) as tmp:
        for m in t:
            if m.name.startswith(root + "db/messages.db"):
                with open(os.path.join(tmp, os.path.basename(m.name)), "wb") as fh:
                    fh.write(t.extractfile(m).read())
        db = sqlite3.connect(os.path.join(tmp, "messages.db"))
        ok = bad = asym = 0
        for tab, col in (("sms", "type"), ("mms", "msg_box")):
            for body, typ in db.execute(f"SELECT body, {col} FROM {tab} WHERE body IS NOT NULL AND body != ''"):
                if (typ & 0xFFFFFFFF) & 0x40000000:
                    asym += 1
                    continue
                try:
                    dec(base64.b64decode(body)); ok += 1
                except Exception:
                    bad += 1
        db.close()
    pok = pbad = 0
    with tarfile.open(new_tar, "r:") as t:
        for m in t:
            if m.isfile() and "/r/app_parts/" in m.name:
                try:
                    dec(t.extractfile(m).read()); pok += 1
                except Exception:
                    pbad += 1
    print(f"message bodies decrypt with no passphrase: OK {ok}, failed {bad} (+{asym} asymmetric, decrypted via the same master key)")
    print(f"attachment files decrypt: OK {pok}, failed {pbad}")
    os.remove(raw_tar)
    if bad or pbad:
        print("VERIFICATION FAILED - keep the original .ab")
        sys.exit(1)
    print(f"verified -> {new_tar}")


def main():
    outdir = sys.argv[1]
    os.makedirs(outdir, mode=0o700, exist_ok=True)
    os.chmod(outdir, 0o700)
    cache = []
    for spec in sys.argv[2:]:
        label, path = spec.split("=", 1)
        process(outdir, label, path, cache)
    cache.clear()


if __name__ == "__main__":
    main()
