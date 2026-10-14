#!/usr/bin/env python3
"""Pack files into an AES-256 7z (encrypted headers) with a password typed twice, then test it with that password.

Usage: pack7z.py ARCHIVE.7z FILE [FILE ...]
The password is read with getpass and passed to 7za once for creating and once for testing; it is never printed.
Prints 7-Zip's verdicts plus a size check of every member against the source files.
"""
import getpass
import os
import re
import subprocess
import sys


def main():
    archive, files = sys.argv[1], sys.argv[2:]
    if os.path.exists(archive):
        sys.exit(f"refusing to overwrite existing {archive}")
    while True:
        pw = getpass.getpass("New archive password (hidden): ")
        if len(pw) < 12:
            print("Use at least 12 characters.")
            continue
        if getpass.getpass("Repeat it (hidden): ") == pw:
            break
        print("They didn't match, try again.")
    r = subprocess.run(["7za", "a", "-t7z", "-mhe=on", "-mx=5", f"-p{pw}", archive, *files], capture_output=True, text=True)
    print("create:", "Everything is Ok" if "Everything is Ok" in r.stdout else "FAILED")
    if r.returncode:
        sys.exit(r.stdout[-500:] + r.stderr[-500:])
    t = subprocess.run(["7za", "t", f"-p{pw}", archive], capture_output=True, text=True)
    print("test with your password:", "Everything is Ok" if "Everything is Ok" in t.stdout else "FAILED")
    l = subprocess.run(["7za", "l", "-slt", f"-p{pw}", archive], capture_output=True, text=True).stdout
    del pw
    sizes = dict(re.findall(r"Path = (.+)\nSize = (\d+)", l))
    for f in files:
        name = os.path.basename(f)
        ok = sizes.get(name) == str(os.path.getsize(f))
        print(f"  {name}: {'present, size matches' if ok else 'MISSING or size differs'}")
    wrong = subprocess.run(["7za", "t", "-pdefinitely-not-it", archive], capture_output=True, text=True)
    print("wrong password rejected:", "yes" if wrong.returncode else "NO")
    sys.exit(0 if t.returncode == 0 and all(sizes.get(os.path.basename(f)) == str(os.path.getsize(f)) for f in files) else 1)


if __name__ == "__main__":
    main()
