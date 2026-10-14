#!/usr/bin/env python3
"""Check that you still know the secrets for an old Signal/TextSecure adb backup (.ab).

Usage: ab_check.py FILE.ab
1. If the .ab is encrypted, asks for the Android backup password and verifies it (header + master-key checksum,
   trying UTF-8 and 8-bit key derivation).
2. Streams the backup until it finds Signal's sp/SecureSMS-Preferences.xml (nothing is written to disk), then asks
   for the old in-app Signal passphrase and verifies it against the stored master secret (MAC check).
Prints only correct/wrong. Passwords are read with getpass and never printed.
"""
import base64
import getpass
import hashlib
import hmac
import io
import os
import sys
import tarfile
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from adb_fix_empty import pkcs12_kdf, pref  # noqa: E402

from cryptography.hazmat.primitives import padding as sympad
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def pbkdf2(pw_bytes, salt, rounds):
    return hashlib.pbkdf2_hmac("sha1", pw_bytes, salt, rounds, 32)


def java_chars_utf8(b):
    # Java: (char) signedByte -> 0x0000..0x007F or 0xFF80..0xFFFF, then PBKDF2WithHmacSHA1 encodes chars as UTF-8
    return "".join(chr(x if x < 0x80 else 0xFF00 | x) for x in b).encode("utf-8")


def unlock(header, password, version):
    user_salt, ck_salt = bytes.fromhex(header[4]), bytes.fromhex(header[5])
    rounds, user_iv, blob = int(header[6]), bytes.fromhex(header[7]), bytes.fromhex(header[8])
    for enc in ("utf-8", "latin-1"):
        try:
            key = pbkdf2(password.encode(enc), user_salt, rounds)
        except UnicodeEncodeError:
            continue
        d = Cipher(algorithms.AES(key), modes.CBC(user_iv)).decryptor().update(blob)
        try:
            u = sympad.PKCS7(128).unpadder()
            d = u.update(d) + u.finalize()
        except ValueError:
            continue
        i = 0
        parts = []
        for _ in range(3):
            n = d[i]
            parts.append(d[i + 1:i + 1 + n])
            i += 1 + n
        iv, mk, ck = parts
        for mkb in ((java_chars_utf8(mk), bytes(x & 0xFF for x in mk)) if version >= 2 else (bytes(mk),)):
            if hmac.compare_digest(pbkdf2(mkb, ck_salt, rounds), ck):
                return mk, iv
    return None


def payload_stream(f, header, version):
    """Yield decompressed tar bytes from the .ab payload (decrypting first if needed)."""
    enc = header[3]
    dec = None
    if enc == "AES-256":
        pw = getpass.getpass("Android backup password (hidden): ")
        r = unlock(header, pw, version)
        del pw
        if not r:
            print("Android backup password: WRONG")
            sys.exit(1)
        print("Android backup password: correct")
        mk, iv = r
        dec = Cipher(algorithms.AES(mk), modes.CBC(iv)).decryptor()
    elif enc != "none":
        print("unsupported encryption:", enc)
        sys.exit(2)
    else:
        print("Android backup password: none (this .ab is not encrypted)")
    z = zlib.decompressobj() if header[2] == "1" else None
    while True:
        chunk = f.read(1 << 20)
        if not chunk:
            break
        if dec:
            chunk = dec.update(chunk)
        yield z.decompress(chunk) if z else chunk


class StreamReader(io.RawIOBase):
    def __init__(self, gen):
        self.gen, self.buf = gen, b""

    def readable(self):
        return True

    def readinto(self, b):
        while not self.buf:
            try:
                self.buf = next(self.gen)
            except StopIteration:
                return 0
        n = min(len(b), len(self.buf))
        b[:n] = self.buf[:n]
        self.buf = self.buf[n:]
        return n


def main():
    with open(sys.argv[1], "rb") as f:
        header = [f.readline().rstrip(b"\n").decode() for _ in range(4)]
        if header[0] != "ANDROID BACKUP":
            print("not an Android backup file")
            sys.exit(2)
        version = int(header[1])
        if header[3] == "AES-256":
            header += [f.readline().rstrip(b"\n").decode() for _ in range(5)]
        tar = tarfile.open(fileobj=io.BufferedReader(StreamReader(payload_stream(f, header, version))), mode="r|")
        for m in tar:
            if m.name.endswith("sp/SecureSMS-Preferences.xml"):
                xml = tar.extractfile(m).read().decode("utf-8")
                break
        else:
            print("Signal preferences not found in this backup")
            sys.exit(2)
    it = int(pref(xml, "int", "passphrase_iterations") or 100)
    salt = base64.b64decode(pref(xml, "string", "mac_salt"))
    ms = base64.b64decode(pref(xml, "string", "master_secret"))
    check = lambda pw: hmac.compare_digest(hmac.new(pkcs12_kdf(pw, salt, 1, it, 16), ms[:-20], hashlib.sha1).digest(), ms[-20:])
    if check("unencrypted"):
        print("Signal app passphrase: none was set in this backup")
        return
    pw = getpass.getpass("Old Signal app passphrase (hidden): ")
    ok = check(pw)
    del pw
    print("Signal app passphrase:", "correct" if ok else "WRONG")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
