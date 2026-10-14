#!/usr/bin/env python3
"""Lossless conversion of 2015-2017 TextSecure/Signal adb dumps into a decrypted new-format backup.

Reads the old databases directly (no signalbackup-tools), decrypts bodies, file names and attachments with
the app's master secret (and the asymmetric key for bodies encrypted while the app was locked), maps every
populated old field to its new-format equivalent, and writes a report of anything with no equivalent.

  adb2v2.py --current J1.json --src 2016=DIR:PASSFILE:0:CUTOFF --src 2017=DIR:PASSFILE:CUTOFF+1:9999999999999
            --files OUTFILESDIR --out merged.json --manifest new_manifest.txt --report report.txt

Each --src takes rows whose RECEIVED time lies in [from, to]. Prints counts only; never message content.
"""
import argparse
import base64
import collections
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import sqlite3
import struct
import sys

from cryptography.hazmat.primitives import padding as sympad
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from adb_fix_empty import pkcs12_kdf, pref  # noqa: E402

# ---- old type bits (TextSecure MmsSmsColumns.Types) ----
BASE_MASK = 0x1F
INCOMING_CALL, OUTGOING_CALL, MISSED_CALL, JOINED = 1, 2, 3, 4
BASE_INBOX, BASE_OUTBOX, BASE_SENDING, BASE_SENT, BASE_SENT_FAILED = 20, 21, 22, 23, 24
BASE_PENDING_SECURE_FALLBACK, BASE_PENDING_INSECURE_FALLBACK = 25, 26
OUT_BASES = {21, 22, 23, 24, 25, 26}
KEY_EXCHANGE, BUNDLE, IDENTITY_UPDATE, IDENTITY_VERIFIED, IDENTITY_DEFAULT = 0x8000, 0x400, 0x200, 0x4000, 0x2000
CORRUPTED, INVALID_VERSION = 0x1000, 0x800
GROUP_UPDATE, GROUP_QUIT, EXPIRATION_UPDATE = 0x10000, 0x20000, 0x40000
PUSH, END_SESSION, SECURE = 0x200000, 0x400000, 0x800000
REMOTE_LEGACY, REMOTE_DUP, REMOTE_NOSESSION, REMOTE_FAILED, REMOTE = 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000
ASYM, SYM = 0x40000000, 0x80000000

OLD_COLOR_TO_BUBBLE = {  # MaterialColor (2016-17) -> nearest BubbleColorPreset
    "red": "SOLID_CRIMSON", "pink": "SOLID_PLUM", "purple": "SOLID_VIOLET", "deep_purple": "SOLID_VIOLET",
    "indigo": "SOLID_INDIGO", "blue": "SOLID_BLUE", "light_blue": "SOLID_BLUE", "cyan": "SOLID_TEAL",
    "teal": "SOLID_TEAL", "green": "SOLID_FOREST", "light_green": "SOLID_WINTERGREEN", "lime": "SOLID_WINTERGREEN",
    "yellow": "SOLID_BURLAP", "amber": "SOLID_BURLAP", "orange": "SOLID_VERMILION", "deep_orange": "SOLID_VERMILION",
    "brown": "SOLID_TAUPE", "grey": "SOLID_STEEL", "blue_grey": "SOLID_STEEL"}


def b64(b):
    return base64.b64encode(b).decode()


def unb64(s):
    return base64.b64decode(s + "=" * (-len(s) % 4))


def aes_cbc_dec(key, iv, ct):
    d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor().update(ct)
    u = sympad.PKCS7(128).unpadder()
    return u.update(d) + u.finalize()


class MasterCipher:
    """TextSecure MasterCipher: iv(16) || AES-128-CBC || HMAC-SHA1(20)."""

    def __init__(self, enc, mac):
        self.enc, self.mac = enc, mac

    def decrypt(self, raw):
        if not hmac.compare_digest(hmac.new(self.mac, raw[:-20], hashlib.sha1).digest(), raw[-20:]):
            raise ValueError("bad mac")
        return aes_cbc_dec(self.enc, raw[:16], raw[16:-20])


class OldDump:
    def __init__(self, label, root, passphrase, lo, hi):
        self.label, self.root, self.lo, self.hi = label, root, lo, hi
        xml = open(f"{root}/sp/SecureSMS-Preferences.xml", encoding="utf-8").read()
        it = int(pref(xml, "int", "passphrase_iterations") or 100)
        mac_salt, enc_salt = unb64(pref(xml, "string", "mac_salt")), unb64(pref(xml, "string", "encryption_salt"))
        ms = unb64(pref(xml, "string", "master_secret"))
        if not hmac.compare_digest(hmac.new(pkcs12_kdf(passphrase, mac_salt, 1, it, 16), ms[:-20], hashlib.sha1).digest(), ms[-20:]):
            raise SystemExit(f"{label}: wrong app passphrase")
        combined = aes_cbc_dec(pkcs12_kdf(passphrase, enc_salt, 1, it, 16), pkcs12_kdf(passphrase, enc_salt, 2, it, 16), ms[:-20])
        self.mc = MasterCipher(combined[:16], combined[16:36])
        priv = pref(xml, "string", "asymmetric_master_secret_curve25519_private")
        self.asym_priv = X25519PrivateKey.from_private_bytes(self.mc.decrypt(unb64(priv))) if priv else None
        appxml_p = f"{root}/sp/org.thoughtcrime.securesms_preferences.xml"
        appxml = open(appxml_p, encoding="utf-8").read() if os.path.exists(appxml_p) else ""
        self.version = int(pref(appxml, "int", "last_version_code") or 0)
        self.own_e164 = canon_e164(pref(appxml, "string", "pref_local_number"))
        self.db = sqlite3.connect(f"{root}/db/messages.db")
        self.db.row_factory = sqlite3.Row
        ca = f"{root}/db/canonical_address.db"
        self.canon = {}
        if os.path.exists(ca):
            for _id, addr in sqlite3.connect(ca).execute("SELECT _id, address FROM canonical_addresses"):
                self.canon[str(_id)] = addr

    def body(self, s, asym):
        if s is None or s == "":
            return ""
        raw = unb64(s)
        if asym:
            pub = X25519PublicKey.from_public_bytes(raw[4:36])  # 3-byte key id || 0x05 || 32-byte point
            secret = self.asym_priv.exchange(pub)
            d = lambda i: hmac.new(secret, struct.pack(">i", i), hashlib.sha256).digest()
            return MasterCipher(d(0)[:16], d(1)[:20]).decrypt(raw[36:]).decode("utf-8")
        return self.mc.decrypt(raw).decode("utf-8")

    def thread_address(self, recipient_ids):
        r = str(recipient_ids)
        if self.version < 276 and r in self.canon:
            return self.canon[r]
        return self.canon.get(r, r) if r.isdigit() and len(r) < 6 else r


def canon_e164(raw, default_cc="1"):
    raw = str(raw or "").strip()
    d = "".join(ch for ch in raw if ch.isdigit())
    if not d:
        return None
    if not raw.startswith("+"):
        if d.startswith("011"):
            d = d[3:]
        elif d.startswith("00"):
            d = d[2:]
        elif len(d) == 10:
            d = default_cc + d
    return d


def padded_size(n):
    return int(max(541, math.floor(math.pow(1.05, math.ceil(math.log(n) / math.log(1.05)))))) if n > 0 else 541


def encrypt_attachment(plain, key64):
    data = plain + b"\0" * (padded_size(len(plain)) - len(plain))
    iv = secrets.token_bytes(16)
    p = sympad.PKCS7(128).padder()
    data = p.update(data) + p.finalize()
    ct = Cipher(algorithms.AES(key64[:32]), modes.CBC(iv)).encryptor().update(data)
    return iv + ct + hmac.new(key64[32:], iv + ct, hashlib.sha256).digest()


def image_size(b):
    """Width/height from image headers (JPEG/PNG/GIF/WebP); None if unknown."""
    try:
        if b[:8] == b"\x89PNG\r\n\x1a\n":
            return struct.unpack(">II", b[16:24])
        if b[:6] in (b"GIF87a", b"GIF89a"):
            return struct.unpack("<HH", b[6:10])
        if b[:4] == b"RIFF" and b[8:12] == b"WEBP":
            if b[12:16] == b"VP8X":
                return (int.from_bytes(b[24:27], "little") + 1, int.from_bytes(b[27:30], "little") + 1)
            if b[12:16] == b"VP8 ":
                return (struct.unpack("<H", b[26:28])[0] & 0x3FFF, struct.unpack("<H", b[28:30])[0] & 0x3FFF)
            if b[12:16] == b"VP8L":
                v = int.from_bytes(b[21:25], "little")
                return ((v & 0x3FFF) + 1, ((v >> 14) & 0x3FFF) + 1)
        if b[:2] == b"\xff\xd8":
            i = 2
            while i < len(b) - 9:
                if b[i] != 0xFF:
                    i += 1
                    continue
                marker = b[i + 1]
                if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
                    i += 2
                    continue
                seg = struct.unpack(">H", b[i + 2:i + 4])[0]
                if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
                    h, w = struct.unpack(">HH", b[i + 5:i + 9])
                    return (w, h)
                i += 2 + seg
    except Exception:
        pass
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--current", required=True)
    ap.add_argument("--src", action="append", required=True, help="LABEL=DIR:PASSFILE:FROM:TO")
    ap.add_argument("--files", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--report", required=True)
    ap.add_argument("--push", action="append", default=[], help="LABEL=push_decrypt.py output JSON")
    a = ap.parse_args()

    S = collections.Counter()      # mapped counts
    U = collections.Counter()      # carried-but-no-equivalent / not carried (reported)

    frames = json.load(open(a.current))
    info, body = frames[0], frames[1:]
    self_id, by_e164, max_rid, chat_by_rid, max_cid = None, {}, 0, {}, 0
    existing_rids = set()
    for f in body:
        if "recipient" in f:
            r = f["recipient"]
            rid = int(r["id"])
            max_rid = max(max_rid, rid)
            if "self" in r:
                self_id = rid
            c = r.get("contact")
            if c and c.get("e164"):
                by_e164.setdefault(canon_e164("+" + str(c["e164"])), rid)
                existing_rids.add(rid)
        elif "chat" in f:
            c = f["chat"]
            max_cid = max(max_cid, int(c["id"]))
            chat_by_rid.setdefault(int(c["recipientId"]), int(c["id"]))
    assert self_id is not None

    new_recipients, new_chats, items, manifest = {}, {}, [], []
    used_rids = set()
    contact_of = {}

    def contact_for(e):
        nonlocal max_rid, max_cid
        rid = by_e164.get(e)
        if rid is None:
            max_rid += 1
            rid = max_rid
            by_e164[e] = rid
            new_recipients[rid] = {"id": str(rid), "contact": {"e164": e, "notRegistered": {}}}
        cid = chat_by_rid.get(rid)
        if cid is None:
            max_cid += 1
            cid = max_cid
            chat_by_rid[rid] = cid
            new_chats[cid] = {"id": str(cid), "recipientId": str(rid)}
        return rid, cid

    def write_media(plain):
        phash = hashlib.sha256(plain).digest()
        lk, rk = secrets.token_bytes(64), secrets.token_bytes(64)
        name = hashlib.sha256(phash + lk).hexdigest()
        os.makedirs(os.path.join(a.files, name[:2]), exist_ok=True)
        with open(os.path.join(a.files, name[:2], name), "wb") as out:
            out.write(encrypt_attachment(plain, lk))
        manifest.append(name)
        return {"key": b64(rk), "size": len(plain), "localKey": b64(lk), "plaintextHash": b64(phash)}

    own_numbers = set()
    for spec in a.src:
        label, rest = spec.split("=", 1)
        root, passfile, lo, hi = rest.rsplit(":", 3)
        d = OldDump(label, root, open(passfile, encoding="utf-8").read().rstrip("\r\n"), int(lo), int(hi))
        db = d.db
        if d.own_e164:
            own_numbers.add(d.own_e164)

        # threads -> contacts/chats
        threads = {}
        for t in db.execute("SELECT * FROM thread"):
            addr = d.thread_address(t["recipient_ids"])
            if str(addr).startswith("__textsecure_group__"):
                threads[t["_id"]] = ("group", addr)
                continue
            e = canon_e164(addr)
            threads[t["_id"]] = ("contact", e)

        rows = []
        for m in db.execute("SELECT *, date AS recv, date_sent AS sent, type AS t, 0 AS is_mms FROM sms WHERE date BETWEEN ? AND ?", (d.lo, d.hi)):
            rows.append(m)
        for m in db.execute("SELECT *, date_received AS recv, date AS sent, msg_box AS t, 1 AS is_mms FROM mms WHERE date_received BETWEEN ? AND ?", (d.lo, d.hi)):
            rows.append(m)
        S[f"{label}: rows in range"] += len(rows)

        for m in rows:
            t = m["t"] & 0xFFFFFFFF
            base = t & BASE_MASK
            kind, e = threads.get(m["thread_id"], ("missing", None))
            if kind == "group":
                U[f"{label}: group (v1) thread rows — GV1 groups have no new-format equivalent; see report"] += 1
                continue
            if not e:
                U[f"{label}: rows whose thread has no phone number"] += 1
                continue
            rid, cid = contact_for(e)
            used_rids.add(rid)
            sent, recv = int(m["sent"] or m["recv"]), int(m["recv"] or m["sent"])
            incoming = not (base in OUT_BASES or base == OUTGOING_CALL)
            item = {"chatId": str(cid), "dateSent": str(sent)}
            exp = int(m["expires_in"] or 0)
            if exp and not (t & EXPIRATION_UPDATE):
                item["expiresInMs"] = str(exp)
                S["timers carried (expiresInMs)"] += 1
                if int(m["expire_started"] or 0):
                    item["expireStartDate"] = str(int(m["expire_started"]))

            # ---- update / event rows (directionless) ----
            upd = None
            if base in (INCOMING_CALL, OUTGOING_CALL, MISSED_CALL):
                direction = "OUTGOING" if base == OUTGOING_CALL else "INCOMING"
                state = "MISSED" if base == MISSED_CALL else "ACCEPTED"
                call_id = int.from_bytes(hashlib.sha256(f"{e}|{sent}|{base}".encode()).digest()[:8], "big") & 0x7FFFFFFFFFFFFFFF
                upd = {"individualCall": {"callId": str(call_id), "type": "AUDIO_CALL", "direction": direction, "state": state,
                                          "startedCallTimestamp": str(sent), "read": bool(m["read"])}}
                S[f"call {direction.lower()} {state.lower()}"] += 1
            elif base == JOINED:
                upd = {"simpleUpdate": {"type": "JOINED_SIGNAL"}}
                S["joined Signal"] += 1
            elif t & EXPIRATION_UPDATE:
                upd = {"expirationTimerChange": {"expiresInMs": str(exp)}}
                S["timer change"] += 1
            elif t & END_SESSION:
                upd = {"simpleUpdate": {"type": "END_SESSION"}}
                S["end session"] += 1
            elif t & (IDENTITY_UPDATE | IDENTITY_VERIFIED | IDENTITY_DEFAULT):
                typ = "IDENTITY_VERIFIED" if t & IDENTITY_VERIFIED else "IDENTITY_DEFAULT" if t & IDENTITY_DEFAULT else "IDENTITY_UPDATE"
                upd = {"simpleUpdate": {"type": typ}}
                S[typ.lower()] += 1
            elif t & (REMOTE_FAILED | REMOTE_NOSESSION | REMOTE_DUP | REMOTE_LEGACY | CORRUPTED | INVALID_VERSION) or (t & KEY_EXCHANGE and t & BUNDLE):
                upd = {"simpleUpdate": {"type": "BAD_DECRYPT"}}
                S["undecryptable-at-receipt (BAD_DECRYPT)"] += 1
            if upd is not None:
                author = self_id if (base == OUTGOING_CALL) else rid
                items.append((recv, {"chatItem": {**item, "authorId": str(author), "directionless": {}, "updateMessage": upd}}))
                continue

            # ---- standard message ----
            std = {}
            try:
                text = d.body(m["body"], bool(t & ASYM))
                if t & ASYM:
                    S["asymmetric bodies decrypted"] += 1
            except Exception:
                U[f"{label}: body could not be decrypted"] += 1
                text = ""
            if text:
                std["text"] = {"body": text}
            if m["is_mms"]:
                atts = []
                for p in db.execute("SELECT * FROM part WHERE mid = ? ORDER BY _id", (m["_id"],)):
                    p = {k: p[k] for k in p.keys()}
                    ptr = {"contentType": p["ct"] or "application/octet-stream"}
                    if p.get("file_name"):
                        try:
                            ptr["fileName"] = d.body(p["file_name"], False)
                            S["attachment file names"] += 1
                        except Exception:
                            U[f"{label}: attachment file name not decryptable"] += 1
                    data_path = p["_data"]
                    plain = None
                    if data_path:
                        fp = os.path.join(root, "r", data_path.split("/org.thoughtcrime.securesms/r/")[-1] if "/r/" in data_path else
                                          data_path.split("/org.thoughtcrime.securesms/")[-1])
                        if not os.path.exists(fp):
                            fp = os.path.join(root, "r", "app_parts", os.path.basename(data_path))
                        try:
                            plain = d.mc.decrypt(open(fp, "rb").read())
                        except Exception:
                            U[f"{label}: attachment file unreadable/undecryptable"] += 1
                    if plain is not None:
                        ptr["locatorInfo"] = write_media(plain)
                        wh = image_size(plain) if (p["ct"] or "").startswith("image/") else None
                        if wh and wh[0] > 0 and wh[1] > 0:
                            ptr["width"], ptr["height"] = int(wh[0]), int(wh[1])
                            S["attachment dimensions (from image header)"] += 1
                        if p["data_size"] and int(p["data_size"]) != len(plain):
                            U[f"{label}: attachment data_size differs from decrypted size (decrypted size used)"] += 1
                        S["attachments with data"] += 1
                        S["attachment bytes"] += len(plain)
                        att = {"pointer": ptr, "wasDownloaded": True}
                    else:
                        # never downloaded (failed in 2017): keep the entry; keep CDN pointer when it is expressible
                        li = {}
                        if p.get("cd") and p.get("cl") and p.get("digest"):
                            li = {"key": b64(unb64(p["cd"])), "size": int(p["data_size"] or 0),
                                  "transitCdnKey": str(p["cl"]), "transitCdnNumber": 0, "encryptedDigest": b64(p["digest"]) if isinstance(p["digest"], bytes) else p["digest"]}
                            S["not-downloaded attachments (CDN pointer kept)"] += 1
                        else:
                            S["not-downloaded attachments (placeholder, nothing to point to)"] += 1
                        ptr["locatorInfo"] = li
                        att = {"pointer": ptr, "wasDownloaded": False}
                    if p.get("voice_note"):
                        att["flag"] = "VOICE_MESSAGE"
                        S["voice notes"] += 1
                    atts.append(att)
                if atts:
                    std["attachments"] = atts
            if not std:
                U[f"{label}: message with neither text nor attachment (nothing to carry)"] += 1
                continue

            item["sms"] = not (t & PUSH)
            if item["sms"]:
                S["SMS (sms=true)"] += 1
            if incoming:
                item["authorId"] = str(rid)
                item["incoming"] = {"dateReceived": str(recv), "dateServerSent": str(sent), "read": bool(m["read"])}
                S["incoming"] += 1
            else:
                item["authorId"] = str(self_id)
                if base == BASE_SENT_FAILED:
                    st = {"failed": {}}
                elif base in (BASE_OUTBOX, BASE_SENDING, BASE_PENDING_SECURE_FALLBACK, BASE_PENDING_INSECURE_FALLBACK):
                    st = {"pending": {}}
                elif int(m["delivery_receipt_count"] or 0) > 0:
                    st = {"delivered": {}}
                else:
                    st = {"sent": {}}
                S[f"outgoing {next(iter(st))}"] += 1
                item["outgoing"] = {"dateReceived": str(recv), "sendStatus": [{"recipientId": str(rid), "timestamp": str(recv), **st}]}
            item["standardMessage"] = std
            items.append((recv, {"chatItem": item}))

        # ---- per-thread / per-contact settings ----
        for rp in db.execute("SELECT * FROM recipient_preferences"):
            addr = d.thread_address(rp["recipient_ids"])
            e = canon_e164(addr)
            rid = by_e164.get(e) if e else None
            cid = chat_by_rid.get(rid) if rid else None
            if cid in new_chats:
                if int(rp["mute_until"] or 0) > 0:
                    new_chats[cid]["muteUntilMs"] = str(int(rp["mute_until"]))
                    S["chat mute carried"] += 1
                if rp["color"] in OLD_COLOR_TO_BUBBLE:
                    new_chats[cid]["style"] = {"bubbleColorPreset": OLD_COLOR_TO_BUBBLE[rp["color"]]}
                    S["chat color carried (nearest preset)"] += 1
            else:
                U[f"{label}: chat settings (mute/color) for a chat that exists now — current settings kept"] += 1
            if rp["notification"]:
                U[f"{label}: custom notification sound — no field in the new format"] += 1
            if int(rp["block"] or 0):
                if rid in new_recipients:
                    new_recipients[rid]["contact"]["blocked"] = True
                    S["blocked carried"] += 1
        idcol = "address" if "address" in [c[1] for c in db.execute("PRAGMA table_info(identities)")] else "recipient"
        for ident in db.execute(f"SELECT {idcol} AS who, key FROM identities"):
            e = canon_e164(d.canon.get(str(ident["who"]), ident["who"]) if idcol == "recipient" else ident["who"])
            rid = by_e164.get(e) if e else None
            if rid in new_recipients:
                new_recipients[rid]["contact"]["identityKey"] = b64(unb64(ident["key"]))
                S["identity keys carried (new contacts)"] += 1
            else:
                U[f"{label}: old identity key for a contact that exists now (current key kept) or never messaged"] += 1
        for g in db.execute("SELECT * FROM groups"):
            U[f"{label}: GV1 group (title, members) — not representable; listed in report"] += 1
        n_push = db.execute("SELECT COUNT(*) FROM push").fetchone()[0]
        if n_push:
            U[f"{label}: undelivered encrypted envelopes in push table (separate step)"] += n_push
        for col_note in ("sms.address_device_id (sender device)", "sms.protocol/reply_path_present/service_center (transport metadata)",
                         "sms/mms.notified (notification shown)", "mms.m_type/st/address (MMS PDU bookkeeping; direction kept)",
                         "part.thumbnail/aspect_ratio (derived; regenerated by the app)", "part.unique_id/fast_preflight_id (local ids)",
                         "thread.snippet/message_count/last_seen/delivery_receipt_count (derived/UI state)",
                         "directory (2016-17 Signal registration cache)"):
            U[f"no new-format field: {col_note}"] += 0

    for spec in a.push:
        label, path = spec.split("=", 1)
        for env in json.load(open(path, encoding="utf-8")):
            e = canon_e164(env["source"])
            if not e:
                U[f"{label}: envelope without sender number"] += 1
                continue
            if e in own_numbers:
                U[f"{label}: undecryptable sync envelope from your own linked device (not representable as a contact message)"] += 1
                continue
            rid, cid = contact_for(e)
            used_rids.add(rid)
            ts = int(env["envelope_ts"])
            if env.get("kind") == "data" and (env.get("body") or env.get("attachments")):
                U[f"{label}: decrypted envelope (unexpected; not auto-imported)"] += 1
                continue
            items.append((ts, {"chatItem": {"chatId": str(cid), "authorId": str(rid), "dateSent": str(ts),
                                            "directionless": {}, "updateMessage": {"simpleUpdate": {"type": "BAD_DECRYPT"}}}}))
            S["undeliverable envelopes recorded as 'bad encrypted message'"] += 1

    items.sort(key=lambda x: x[0])
    out, kinds = [info], [next(iter(f)) for f in body]
    last_r = max(i for i, k in enumerate(kinds) if k == "recipient")
    last_c = max(i for i, k in enumerate(kinds) if k == "chat")
    first_i = min(i for i, k in enumerate(kinds) if k == "chatItem")
    for i, f in enumerate(body):
        if i == first_i:
            out.extend(it for _, it in items)
        out.append(f)
        if i == last_r:
            out.extend({"recipient": r} for r in new_recipients.values())
        if i == last_c:
            out.extend({"chat": c} for c in new_chats.values())
    json.dump(out, open(a.out, "w", encoding="utf-8"), ensure_ascii=False)
    open(a.manifest, "w").write("".join(n + "\n" for n in manifest))

    lines = [f"old items written: {len(items)}", f"contacts used by old history: {len(used_rids)} ({len(used_rids & existing_rids)} matched existing by number, {len(new_recipients)} created)",
             f"chats created: {len(new_chats)}", f"frames: {len(frames)} -> {len(out)}", "", "MAPPED:"]
    lines += [f"  {k}: {v}" for k, v in sorted(S.items())]
    lines += ["", "NOT CARRIED / NO EQUIVALENT:"] + [f"  {k}: {v}" for k, v in sorted(U.items())]
    open(a.report, "w").write("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
