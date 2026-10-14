# signal-adb2v2

Lossless migration of 2014–2017 TextSecure/Signal **adb backups** into a modern Signal **on-device backup**
(the backup-v2 folder format: `SignalBackups/signal-backup-*/{main,metadata,files}` plus the shared
`SignalBackups/files/`). The result restores on a current Android phone, with old photos back in their
conversations at their original times.

Proven end to end in Oct 2026: years of messages and photos from two adb dumps were merged into a live backup,
restored on a phone, and re-exported by the app intact.

## Pieces
| File | Purpose |
|---|---|
| `ab_extract.py` | Decrypts Android `.ab` adb backups (v1–v5, AES-256 or unencrypted) in pure Python; reads the password from a hidden prompt, so shell quoting can't mangle it. |
| `adb_passtest.py` | Finds the old in-app TextSecure passphrase among candidate lines (master_secret MAC check; never prints secrets). |
| `adb_fix_empty.py` | Helper module (PKCS#12 KDF, prefs parsing). Its CLI also works around a signalbackup-tools bug (not needed with `adb2v2.py`). |
| `adb2v2.py` | **The converter.** Reads the old `messages.db` directly, decrypts bodies, file names and attachments (symmetric *and* asymmetric), maps every populated field to backup.proto, writes encrypted media into `files/`, and splices the result into a decrypted current backup. Writes a report of anything that has no new-format equivalent. |
| `push_decrypt.py` + `libsignal-example/old_push_decrypt.rs` | Attempts to decrypt envelopes left unprocessed in the old `push` table using the dump's saved sessions (libsignal-protocol). Undecryptable ones become `BAD_DECRYPT` events. |
| `verify_media.py` | Verifies local-backup media exactly as `RestoreLocalAttachmentJob` does (name, HMAC, AES-CBC, plaintext hash). |
| `ab_check.py` | Confirms you still know an `.ab`'s Android backup password and the old in-app passphrase (prints correct/wrong only). |
| `ab_rewrap.py` | Re-wraps an `.ab`'s master secret to the built-in "unencrypted" passphrase, writes a plain tar, and verifies it is lossless (every other member byte-identical; every body and attachment decrypts). Protect the output immediately. |
| `pack7z.py` | Packs files into an AES-256 7z with encrypted headers, a password typed twice, then tests it. |
| `bk_passcheck.py` | Checks a 30-digit passphrase against a *legacy* `.backup` file from its header in about a second. |

## Pipeline
1. Build libsignal's tools: `cargo build --release -p libsignal-message-backup --examples --bins` (needs `protoc` on PATH).
   Copy `old_push_decrypt.rs` into `rust/protocol/examples/` and build `-p libsignal-protocol --example old_push_decrypt`.
2. Decrypt the phone's current snapshot:
   `decrypt_backup --account-entropy <64-char recovery key> --metadata <snap>/metadata <snap>/main > current.json`
3. Convert and merge (split two dumps at the last received timestamp of the older one):
   ```
   adb2v2.py --current current.json \
     --src OLD=<adbdir>:<passfile>:0:<cutoff> --src NEW=<adbdir>:<passfile>:<cutoff+1>:9999999999999 \
     --push OLD=push_old.json --push NEW=push_new.json \
     --files staged_files/ --out merged.json --manifest new_manifest.txt --report report.txt
   ```
4. `json_to_binproto merged.json > merged.bin`, then
   `encrypt_backup --format legacy --account-entropy KEY --metadata <snap>/metadata merged.bin > main`
   (use **legacy**: phone-written local snapshots have no `SBACKUP` header), then `validator ... main` must exit 0.
5. New snapshot dir `signal-backup-<later timestamp>/`: copy `metadata`, put the new `main`, and write `files` as the
   old varint-delimited `FilesFrame{mediaName}` list plus the new names. Move the staged media into `SignalBackups/files/xx/`.
   `verify_media.py merged.json SignalBackups/files --only-new new_manifest.txt`.
6. Copy the whole `SignalBackups` folder to the phone **as one zip** (thousands of small files over MTP or Wi-Fi silently drop
   some, and the app then marks those photos as failed for good). Verify the file count, then reinstall Signal and choose
   *Restore on-device backup*.

## Local media format (from Signal-Android source)
`mediaName = hex(sha256(plaintextHash || localKey))`, stored at `files/<first 2 hex>/<mediaName>`. The content is
`iv(16) || AES-256-CBC(PKCS7)(plaintext zero-padded to max(541, floor(1.05^ceil(log_1.05(n))))) || HMAC-SHA256(32)`,
with the 64-byte `localKey` split as aes(32)|mac(32). A FilePointer with `plaintextHash` must also carry `key` (64 bytes).

## Gotchas found
- Signal keeps an `individualCall` only if it has a `callId` (otherwise the next export drops it).
- Undecryptable envelopes from your *own* linked devices are not contact messages, so skip them.
- Python's `json.dump` must use `ensure_ascii=False`; libsignal's JSON parser rejects `\u` surrogate escapes.
- A restore marks any attachment whose file is missing from the phone's `files/` as permanently failed; there is no retry.

Secrets are only ever read from files or prompts and never printed. Treat all intermediate JSON as plaintext message data.

## Upstream reports
Findings were shared with signalbackup-tools (which accepts suggestions as issues, not pull requests):
- [#398](https://github.com/bepaald/signalbackup-tools/issues/398): `--importadbbackup` drops messages whose encrypted body is empty, together with their photos
- [#226 follow-up](https://github.com/bepaald/signalbackup-tools/issues/226#issuecomment-6157666588): decrypting asymmetric bodies; type bits lost on import
- [#382 follow-up](https://github.com/bepaald/signalbackup-tools/issues/382#issuecomment-6157706854): a merged local v2 backup restored on a real phone, and what the app keeps

## License
AGPL-3.0 (see LICENSE). `libsignal-example/old_push_decrypt.rs` is written as an example for
[libsignal](https://github.com/signalapp/libsignal), which is AGPL-3.0.
