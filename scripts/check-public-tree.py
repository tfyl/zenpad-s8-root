#!/usr/bin/env python3
"""Check publication files and optional Git history without printing matched values."""

import argparse
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys


EXCLUDED_SUFFIXES = {
    ".img", ".apk", ".png", ".jpg", ".jpeg", ".bin", ".ab", ".db",
    ".sqlite", ".sqlite3", ".bundle", ".pem", ".key", ".p12", ".jks",
    ".keystore", ".pcap", ".pcapng", ".zip", ".tar", ".tgz", ".gz",
    ".xz", ".7z", ".log",
}
EXCLUDED_PARTS = {
    "screens", "captures", "backups", "private", "sdcard", "userdata",
    ".android", ".aws", ".ssh", ".config",
}
PATTERNS = {
    "Google OAuth token": re.compile(rb"ya29\.[A-Za-z0-9._-]{12,}"),
    "Google refresh token": re.compile(rb"\b1//[A-Za-z0-9_-]{30,}"),
    "Google API key": re.compile(rb"AIza[A-Za-z0-9_-]{35}"),
    "GitHub token": re.compile(rb"gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}"),
    "AWS access key": re.compile(rb"(?:AKIA|ASIA)[A-Z0-9]{16}"),
    "Slack token": re.compile(rb"xox[baprs]-[A-Za-z0-9-]{15,}"),
    "private key": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"),
    "bearer credential": re.compile(rb"Authorization:[ \t]*Bearer[ \t]+[A-Za-z0-9._~+/-]{12,}", re.I),
    "session cookie": re.compile(rb"(?:Cookie|Set-Cookie):[ \t]*[A-Za-z0-9_.-]+=[A-Za-z0-9._~+/%=-]{12,}", re.I),
    "device serial": re.compile(rb"\b(?:H[0-9][A-Z]{3}[A-Z0-9]{8,15}|CN[0-9]{12,16})\b"),
    "personal home path": re.compile(rb"/(?:home|Users)/[A-Za-z0-9_.-]+/"),
}
EMAIL = re.compile(rb"[A-Za-z0-9_.+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
# Public upstream/GitHub attribution and reserved documentation domains.
PUBLIC_EMAIL_DOMAINS = {
    b"openssl.org", b"gnu.org", b"google.com", b"android.com", b"intel.com",
    b"asus.com", b"dkuug.dk", b"example.com", b"example.invalid",
    b"users.noreply.github.com",
}
EXCLUDED_HEADERS = (
    b"ANDROID!", b"ANDROID BACKUP\n", b"SQLite format 3\0", b"\x89PNG\r\n\x1a\n",
    b"\xff\xd8\xff", b"PK\x03\x04", b"PK\x05\x06", b"\x1f\x8b", b"\xfd7zXZ\0",
    b"7z\xbc\xaf\x27\x1c",
)
UTF16_ASCII = (
    (re.compile(rb"(?:[\x09\x0a\x0d\x20-\x7e]\x00){4,}"), "utf-16-le"),
    (re.compile(rb"(?:\x00[\x09\x0a\x0d\x20-\x7e]){4,}"), "utf-16-be"),
)


def git_environment():
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
               GIT_CONFIG_SYSTEM=os.devnull, GIT_TERMINAL_PROMPT="0")
    return env


def git(root, *args):
    return subprocess.check_output(
        ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
         "-C", str(root), *args], env=git_environment()
    )


def tree_entries(records, index=False):
    for record in records.split(b"\0"):
        if not record:
            continue
        fields, name = record.split(b"\t", 1)
        mode, middle, last = fields.decode().split()
        oid, stage = (middle, last) if index else (last, "0")
        yield mode, oid, stage, name.decode()


def path_issue(name):
    path = PurePosixPath(name)
    if path.suffix.lower() in EXCLUDED_SUFFIXES or EXCLUDED_PARTS.intersection(part.lower() for part in path.parts):
        return True
    if path.name.endswith(".env") and path.name != "config.example.env":
        return True
    name = path.name.lower()
    if any(marker in name for marker in (".db-", ".sqlite-", ".sqlite3-")):
        return True
    return name.startswith(("handoff-", "checkpoint-", "run-history-", "accounts", "auth_tokens", "cookies", "login_data"))


def inspect(data, denylist):
    found = {kind for kind, pattern in PATTERNS.items() if pattern.search(data)}
    if any(m.group(1).lower() not in PUBLIC_EMAIL_DOMAINS for m in EMAIL.finditer(data)):
        found.add("unreviewed email address")
    if any(value in data for value in denylist):
        found.add("private denylist match")
    return sorted(found)


def inspect_file(data, denylist):
    found = set(inspect(data, denylist))
    if data.startswith(EXCLUDED_HEADERS):
        found.add("excluded captured or compressed format requires review")
    for pattern, encoding in UTF16_ASCII:
        for match in pattern.finditer(data):
            found.update(inspect(match.group().decode(encoding).encode(), denylist))
    if any(value.decode(errors="replace").encode(encoding) in data
           for value in denylist for encoding in ("utf-16-le", "utf-16-be")):
        found.add("private denylist match")
    return sorted(found)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--history", action="store_true", help="Also inspect reachable history and commit metadata")
    parser.add_argument("--index", action="store_true", help="Inspect staged blobs instead of working-tree files")
    parser.add_argument("--denylist", type=Path, help="Private local file of exact strings to exclude; never copied to a release")
    args = parser.parse_args()
    root = args.root.resolve()
    denylist = []
    if args.denylist:
        denylist = [line.strip() for line in args.denylist.read_bytes().splitlines() if line.strip()]
    failures = []
    def check_name(name, label=None):
        label = name if label is None else label
        if path_issue(name):
            failures.append((label, "excluded artifact type or path"))
        for kind in inspect(name.encode(), denylist):
            failures.append((label, kind))

    entries = list(tree_entries(git(root, "ls-files", "--stage", "-z"), index=True))
    for mode, oid, stage, name in entries:
        check_name(name)
        if stage != "0" or mode not in {"100644", "100755"}:
            failures.append((name, "unmerged, symlink, or non-regular tracked entry requires review"))
            continue
        if args.index:
            data = git(root, "cat-file", "blob", oid)
        else:
            path = root / name
            if not path.is_file():
                failures.append((name, "tracked path is missing; stage intended removals before checking"))
                continue
            if path.is_symlink() or not path.resolve().is_relative_to(root):
                failures.append((name, "symlink requires review"))
                continue
            data = path.read_bytes()
        for kind in inspect_file(data, denylist):
            failures.append((name, kind))
    if args.history:
        commits = git(root, "log", "--all", "--format=%an <%ae>%n%cn <%ce>%n%B")
        for kind in inspect(commits, denylist):
            failures.append(("Git commit metadata", kind))
        refs = git(root, "for-each-ref", "--format=%(refname)")
        for kind in inspect(refs, denylist):
            failures.append(("Git reference names", kind))
        for commit in git(root, "rev-list", "--all").decode().splitlines():
            for mode, _, _, name in tree_entries(git(root, "ls-tree", "-r", "-z", commit)):
                check_name(name, "history:" + name)
                if mode not in {"100644", "100755"}:
                    failures.append(("history:" + name, "non-regular historical entry requires review"))
        objects = git(root, "rev-list", "--objects", "--all").decode().splitlines()
        seen = set()
        for line in objects:
            oid, _, name = line.partition(" ")
            kind = git(root, "cat-file", "-t", oid).strip()
            if kind == b"tag":
                for finding in inspect(git(root, "cat-file", "tag", oid), denylist):
                    failures.append(("Git annotated tag metadata", finding))
                continue
            if kind != b"blob":
                continue
            if oid in seen:
                continue
            seen.add(oid)
            for kind in inspect_file(git(root, "cat-file", "blob", oid), denylist):
                failures.append(("history:" + (name or oid), kind))
    for name, kind in sorted(set(failures)):
        label = name
        if inspect(name.encode(), denylist):
            label = "<redacted path " + hashlib.sha256(name.encode()).hexdigest()[:12] + ">"
        print(f"REVIEW {label}: {kind}")
    if failures:
        print("Publication check failed. Matched values are deliberately omitted.")
        return 1
    print(f"Publication check passed for {len(entries)} tracked files" + (" and reachable Git history." if args.history else "."))
    print("Pattern checks supplement artifact review; they cannot prove the absence of every secret.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
