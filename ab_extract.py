#!/usr/bin/env python3
"""Decrypt & unpack an encrypted adb backup (.ab) to a .tar, using the standard
UTF-8 PBKDF2 key derivation that Android 5+/6 actually used (which abe's unpack
gets wrong for some devices, throwing BadPaddingException on a correct password).

The password is read with getpass; it is never printed, logged, or written.

usage: .venv/bin/python -I ab_extract.py <in.ab> <out.tar>
"""
import getpass
import hashlib
import sys
import zlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def parse_header(f):
    magic = f.readline().rstrip(b"\n")
    if magic != b"ANDROID BACKUP":
        raise SystemExit("not an adb backup file")
    version = int(f.readline())
    compressed = int(f.readline())
    algo = f.readline().rstrip(b"\n")
    if algo != b"AES-256":
        raise SystemExit(f"not encrypted (algorithm={algo!r}); just rename to .tar after stripping 4 header lines")
    user_salt = bytes.fromhex(f.readline().decode())
    ck_salt = bytes.fromhex(f.readline().decode())
    rounds = int(f.readline())
    user_iv = bytes.fromhex(f.readline().decode())
    mk_blob = bytes.fromhex(f.readline().decode())
    return version, compressed, user_salt, ck_salt, rounds, user_iv, mk_blob


def pbkdf2(pw_bytes, salt, rounds):
    return hashlib.pbkdf2_hmac("sha1", pw_bytes, salt, rounds, 32)


def unpad(b):
    pad = b[-1]
    if not 1 <= pad <= 16 or b[-pad:] != bytes([pad]) * pad:
        raise SystemExit("bad padding after decrypt (wrong password?)")
    return b[:-pad]


def _pw_bytes(pw, utf8):
    # AOSP: password is fed to PBKDF2 either as UTF-8 (v2+/post-4.4) or 8-bit (legacy)
    return pw.encode("utf-8") if utf8 else bytes((ord(c) & 0xFF) for c in pw)


def _ck_bytes(mk, utf8):
    # Android casts each master-key byte to a Java char, then PBKDF2s it
    chars = "".join(chr(x if x < 0x80 else 0xFF00 | x) for x in mk)
    return chars.encode("utf-8", "surrogatepass") if utf8 else bytes((ord(c) & 0xFF) for c in chars)


def master_key(pw, user_salt, rounds, user_iv, mk_blob, ck_salt, version):
    default_utf = version >= 2
    for utf8 in (default_utf, not default_utf):
        user_key = pbkdf2(_pw_bytes(pw, utf8), user_salt, rounds)
        dec = Cipher(algorithms.AES(user_key), modes.CBC(user_iv)).decryptor()
        raw = dec.update(mk_blob) + dec.finalize()
        pad = raw[-1]
        if not 1 <= pad <= 16 or raw[-pad:] != bytes([pad]) * pad:
            continue
        blob = raw[:-pad]
        try:
            o = 0
            n = blob[o]; o += 1; mk_iv = blob[o:o + n]; o += n
            n = blob[o]; o += 1; mk = blob[o:o + n]; o += n
            n = blob[o]; o += 1; ck = blob[o:o + n]
        except IndexError:
            continue
        for ck_utf in (utf8, not utf8):
            if pbkdf2(_ck_bytes(mk, ck_utf), ck_salt, rounds) == ck:
                return mk, mk_iv
    raise SystemExit("wrong password, or unsupported key derivation")


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    inp, outp = sys.argv[1], sys.argv[2]
    with open(inp, "rb") as f:
        version, compressed, user_salt, ck_salt, rounds, user_iv, mk_blob = parse_header(f)
        print(f"v{version}, compressed={compressed}, {rounds} rounds")
        pw = getpass.getpass("Password: ")
        mk, mk_iv = master_key(pw, user_salt, rounds, user_iv, mk_blob, ck_salt, version)
        del pw
        print("  key OK — decrypting payload...")
        dec = Cipher(algorithms.AES(mk), modes.CBC(mk_iv)).decryptor()
        inflater = zlib.decompressobj()
        written = 0
        tail = b""
        with open(outp, "wb") as out:
            while True:
                chunk = f.read(1 << 20)
                if not chunk:
                    break
                tail += dec.update(chunk)
                # hold back last block until EOF so we can strip PKCS#5 padding
                keep = (len(tail) - 1) % 16 + 1 + 16
                emit, tail = tail[:-keep] if len(tail) > keep else b"", tail[-keep:] if len(tail) > keep else tail
                if emit:
                    data = inflater.decompress(emit) if compressed else emit
                    out.write(data); written += len(data)
            tail += dec.finalize()
            tail = unpad(tail)
            data = inflater.decompress(tail) + inflater.flush() if compressed else tail
            out.write(data); written += len(data)
    print(f"  done -> {outp} ({written} bytes)")


if __name__ == "__main__":
    main()
