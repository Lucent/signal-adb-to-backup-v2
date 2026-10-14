#!/usr/bin/env python3
"""Check a 30-digit passphrase against a legacy Signal .backup file without decrypting it.

Reads only the plaintext header (salt, IV, version) and the first encrypted frame, derives the keys the way
Signal does (SHA-512 x250000 -> HKDF "Backup Export"), and verifies that frame's HMAC.
The passphrase is read from stdin and never printed. Exit 0 = correct, 1 = wrong, 2 = unreadable file.
"""
import hashlib
import hmac
import struct
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def varint(buf, i):
    shift = val = 0
    while True:
        b = buf[i]
        i += 1
        val |= (b & 0x7F) << shift
        if not b & 0x80:
            return val, i
        shift += 7


def fields(buf):
    """Yield (field number, wire type, value) for one protobuf message."""
    i = 0
    while i < len(buf):
        key, i = varint(buf, i)
        num, wt = key >> 3, key & 7
        if wt == 0:
            val, i = varint(buf, i)
        elif wt == 2:
            n, i = varint(buf, i)
            val, i = buf[i:i + n], i + n
        elif wt == 1:
            val, i = buf[i:i + 8], i + 8
        elif wt == 5:
            val, i = buf[i:i + 4], i + 4
        else:
            raise ValueError("bad wire type")
        yield num, wt, val


def read_header(f):
    (hlen,) = struct.unpack(">I", f.read(4))
    frame = f.read(hlen)
    header = next(v for n, wt, v in fields(frame) if n == 1 and wt == 2)  # BackupFrame.header
    h = {n: v for n, _, v in fields(header)}  # Header: 1 iv, 2 salt, 3 version
    return h[1], h.get(2, b""), h.get(3, 0)


def derive(passphrase, salt):
    inp = passphrase.encode()
    h = inp
    for i in range(250000):
        d = hashlib.sha512()
        if i == 0 and salt:
            d.update(salt)
        d.update(h)
        d.update(inp)
        h = d.digest()
    okm = HKDF(algorithm=hashes.SHA256(), length=64, salt=None, info=b"Backup Export").derive(h[:32])
    return okm[:32], okm[32:]


def check(path, passphrase):
    with open(path, "rb") as f:
        iv, salt, version = read_header(f)
        cipherkey, mackey = derive(passphrase, salt)
        rawlen = f.read(4)
        candidates = []
        if version >= 1:  # frame length is encrypted and covered by the MAC
            dec = Cipher(algorithms.AES(cipherkey), modes.CTR(iv)).decryptor().update(rawlen)
            candidates.append((struct.unpack(">I", dec)[0], rawlen))
        else:
            candidates.append((struct.unpack(">I", rawlen)[0], b""))
        pos = f.tell()
        for flen, macprefix in candidates:
            if not 10 < flen < 64 * 1024 * 1024:
                continue
            f.seek(pos)
            frame = f.read(flen)
            if len(frame) != flen:
                continue
            ours = hmac.new(mackey, macprefix + frame[:-10], hashlib.sha256).digest()[:10]
            if hmac.compare_digest(ours, frame[-10:]):
                return True
    return False


if __name__ == "__main__":
    # usage: bk_passcheck.py BACKUP [SAVE_TO] < candidates (one per line; anything but digits is ignored)
    # On a match, writes the passphrase to SAVE_TO (mode 600) and exits 0.
    import os
    seen = set()
    for line in sys.stdin:
        pw = "".join(c for c in line if c.isdigit())
        if len(pw) != 30 or pw in seen:
            continue
        seen.add(pw)
        try:
            ok = check(sys.argv[1], pw)
        except (OSError, ValueError, StopIteration, KeyError, struct.error):
            sys.exit(2)
        if ok:
            if len(sys.argv) > 2:
                fd = os.open(sys.argv[2], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w") as out:
                    out.write(pw + "\n")
            sys.exit(0)
    sys.exit(1)
