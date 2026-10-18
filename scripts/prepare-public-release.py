#!/usr/bin/env python3
"""Create a checked publication copy with one new root commit and no remote."""

import argparse
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys


def run(*args, cwd, **kwargs):
    return subprocess.run(args, cwd=cwd, check=True, **kwargs)


def git_environment():
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
               GIT_CONFIG_SYSTEM=os.devnull, GIT_TERMINAL_PROMPT="0")
    return env


def git(cwd, *args, capture=False):
    command = ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
               "-c", "commit.gpgsign=false", *args]
    if capture:
        return subprocess.check_output(command, cwd=cwd, env=git_environment())
    return run(*command, cwd=cwd, env=git_environment())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--denylist", type=Path, help="Private audit input; never copied")
    parser.add_argument("--author-name", help="Explicit public commit author; defaults to a neutral identity")
    parser.add_argument("--author-email", help="Explicit public commit email, such as a GitHub noreply address")
    args = parser.parse_args()
    if bool(args.author_name) != bool(args.author_email):
        parser.error("--author-name and --author-email must be supplied together")
    author_name = args.author_name or "Z580CA contributors"
    author_email = args.author_email or "contributors@example.invalid"
    source = Path(__file__).resolve().parents[1]
    destination = args.destination.resolve()
    if destination == source or source in destination.parents:
        parser.error("publication destination must be outside the source repository")
    if destination.exists() and (not destination.is_dir() or any(destination.iterdir())):
        parser.error("destination must be empty; existing repositories are never overwritten")
    if git(source, "rev-parse", "--show-toplevel", capture=True).decode().strip() != str(source):
        parser.error("source must be the repository root")
    if git(source, "diff", "--name-only", "--", capture=True):
        parser.error("review and stage all tracked changes before preparing a release")
    untracked = git(source, "ls-files", "--others", "--exclude-standard", "-z", capture=True)
    if untracked:
        parser.error("review and stage untracked files before preparing a release")
    checker = source / "scripts" / "check-public-tree.py"
    checks = [sys.executable, str(checker)]
    if args.denylist:
        checks.extend(["--denylist", str(args.denylist.resolve())])
    run(*checks, "--index", cwd=source, env=git_environment())
    records = git(source, "ls-files", "--stage", "-z", capture=True).split(b"\0")
    entries = []
    for record in filter(None, records):
        fields, name_bytes = record.split(b"\t", 1)
        mode, oid, stage = fields.decode().split()
        name = name_bytes.decode()
        path = PurePosixPath(name)
        if stage != "0" or mode not in {"100644", "100755"}:
            parser.error("only resolved regular files may be exported")
        if path.is_absolute() or ".." in path.parts:
            parser.error("invalid staged path")
        entries.append((mode, oid, name))
    destination.mkdir(parents=True, exist_ok=True)
    for mode, oid, name in entries:
        dst = destination / name
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(git(source, "cat-file", "blob", oid, capture=True))
        dst.chmod(0o755 if mode == "100755" else 0o644)
    git(destination, "init", "--quiet", "--initial-branch=main", "--template=")
    git(destination, "config", "--local", "user.name", author_name)
    git(destination, "config", "--local", "user.email", author_email)
    # All files here came from the reviewed index, including deliberately tracked
    # files that match an ignore rule. Do not silently lose them on re-add.
    git(destination, "add", "--force", "--all")
    exported = git(destination, "ls-files", "--stage", "-z", capture=True)
    if exported != b"\0".join(record for record in records if record) + b"\0":
        raise RuntimeError("publication index differs from the reviewed source index")
    identity = git_environment()
    identity.update(
        GIT_AUTHOR_NAME=author_name,
        GIT_COMMITTER_NAME=author_name,
        GIT_AUTHOR_EMAIL=author_email,
        GIT_COMMITTER_EMAIL=author_email,
    )
    run(
        "git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false",
        "commit", "--quiet", "-m", "Document ZenPad S 8.0 unlock and root",
        cwd=destination, env=identity,
    )
    run(*checks, "--root", str(destination), "--history", cwd=source, env=git_environment())
    count = git(destination, "rev-list", "--all", "--count", capture=True).strip()
    if count != b"1" or git(destination, "remote", capture=True).strip():
        raise RuntimeError("publication copy must have one commit and no remotes")
    print(f"Prepared publication copy: {destination}")
    print("One new commit; no original Git history, archives, ignored files, or remote.")


if __name__ == "__main__":
    main()
