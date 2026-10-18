# Privacy and publication

The source distribution documents the implementation and vendor-firmware
research. It excludes screenshots, raw session handoffs, connection identities,
target-derived executable copies, firmware images, APKs, and device captures.
Scripts require explicit local connection settings.

Vendor references retain upstream author and contact comments, including an
individual attribution in `reference/ww-5.5.1/ramdisk/init.logtool.rc`. These are
firmware provenance, not the repository owner's account or connection settings.
The reference bytes are preserved; the checker's upstream-domain allowlist is
not a review of every individual identifier.

Project authorship is public. GitHub usernames and GitHub-provided `noreply`
addresses may identify commit authors; account/session contents and local
connection settings remain excluded.

Device images can contain more information than their filenames suggest.
Userdata, app storage, account databases, Google session material, browser data,
and storage captures must remain outside the repository. A factory reset or a
missing text-search match does not establish that an old image is safe to share.

## Release checks

```bash
python3 scripts/check-public-tree.py
```

The check reports paths and finding categories without echoing matched values;
paths containing a match are replaced by a digest. It checks filenames and
contents for credential patterns, device serials, local home paths, and
unreviewed email addresses. Common capture/archive headers and ASCII text in
UTF-16 are also checked. A private local
denylist can supplement the patterns:

```bash
python3 scripts/check-public-tree.py --denylist /path/outside/repo/private-denylist.txt
```

The denylist itself must stay outside the release. Use `--index` to check staged
blob bytes rather than working files. Pattern checks do not unpack containers,
read screenshot pixels, recognize every encoding, or detect every credential.
They do not replace review of artifact provenance and formats.

## Git history

Removing a file from the current tree does not remove it from earlier commits.
Commit authors and email addresses are also stored in history. The original
history includes device identifiers, connection/home paths, and screenshots.
It is kept in a separate private repository. Do not push its old branches or
tags to the public repository.

A publication copy must be exported from the reviewed tree into a new repository.
After reviewing and staging the intended files, prepare it with:

```bash
python3 scripts/prepare-public-release.py /path/to/publication-copy
```

The default commit identity is neutral. To retain public GitHub authorship,
supply both `--author-name YOUR_USERNAME` and
`--author-email YOUR_GITHUB_NOREPLY_ADDRESS`. These explicit values override
ambient author settings and are checked with the resulting history. Personal
mailbox addresses need separate review.

The helper rejects unstaged tracked changes and untracked files that are not
ignored. It copies regular files from staged Git blobs, preserving their indexed
executable modes, and verifies that the new index has the same paths and bytes.
It ignores inherited Git overrides and global/system configuration, disables
hooks, and initializes with an empty template. The result has one new root commit
and no remote. The original `.git`, archives, and local ignored files are not
copied. A nonempty destination is never overwritten.

You can also run the history check independently:

```bash
python3 scripts/check-public-tree.py --root /path/to/publication-copy --history
```

The history check covers reachable commit identities/messages, annotated tags,
reference names, historical paths, and blobs. Reflogs, unreachable objects,
local Git configuration, hosting metadata, and copies elsewhere need separate
inspection. Run the check again after adding a release tag or commit.

Changing the original repository's visibility would expose its old commits.
Publishing a new snapshot does not retroactively erase files already stored in
the private repository or other clones.
