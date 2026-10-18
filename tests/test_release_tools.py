"""Regression fixtures for publication boundaries; no network or device access."""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def clean_env():
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
    return env


class ReleaseToolsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.source = self.base / "source"
        self.source.mkdir()
        (self.source / "scripts").mkdir()
        for name in ("check-public-tree.py", "prepare-public-release.py"):
            shutil.copy2(ROOT / "scripts" / name, self.source / "scripts" / name)
        (self.source / "README.md").write_text("Public fixture\n")
        self.git("init", "-q", "--initial-branch=main", "--template=")
        self.git("config", "user.name", "Fixture contributors")
        self.git("config", "user.email", "fixture@example.invalid")
        self.commit()

    def git(self, *args, cwd=None, env=None):
        result = subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", *args],
            cwd=cwd or self.source, env=env or clean_env(), capture_output=True, check=True,
        )
        return result.stdout

    def commit(self):
        self.git("add", "--all")
        self.git("commit", "-qm", "Public fixture")

    def command(self, name, *args, env=None):
        return subprocess.run(
            [sys.executable, str(self.source / "scripts" / name), *map(str, args)],
            env=env or clean_env(), capture_output=True, text=True, timeout=30,
        )

    def export(self, *args, env=None):
        return self.command("prepare-public-release.py", self.base / "release", *args, env=env)

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_git_environment_cannot_redirect_export_or_identity(self):
        before_head = self.git("rev-parse", "HEAD")
        before_config = (self.source / ".git/config").read_bytes()
        env = clean_env() | {
            "GIT_DIR": str(self.source / ".git"),
            "GIT_WORK_TREE": str(self.source),
            "GIT_INDEX_FILE": str(self.source / ".git/index"),
            "GIT_AUTHOR_NAME": "Ambient fixture",
            "GIT_AUTHOR_EMAIL": "ambient@example.invalid",
            "GIT_COMMITTER_NAME": "Ambient fixture",
            "GIT_COMMITTER_EMAIL": "ambient@example.invalid",
        }
        self.assert_success(self.export(env=env))
        release = self.base / "release"
        self.assertEqual(self.git("rev-parse", "HEAD"), before_head)
        self.assertEqual((self.source / ".git/config").read_bytes(), before_config)
        self.assertEqual(self.git("rev-list", "--all", "--count", cwd=release).strip(), b"1")
        self.assertEqual(self.git("remote", cwd=release), b"")
        metadata = self.git("log", "--format=%an <%ae>%n%cn <%ce>", cwd=release)
        self.assertNotIn(b"Ambient", metadata)
        self.assertIn(b"contributors@example.invalid", metadata)
        self.assertEqual(self.git("ls-files", "--stage", "-z"),
                         self.git("ls-files", "--stage", "-z", cwd=release))

    def test_templates_global_ignores_and_hooks_are_not_inherited(self):
        template = self.base / "template"
        (template / "hooks").mkdir(parents=True)
        (template / "private-note").write_text("Private fixture note")
        (template / "config").write_text("[credential]\n username = fixture\n")
        marker = self.base / "hook-ran"
        hook = template / "hooks/pre-commit"
        hook.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 1\n")
        hook.chmod(0o755)
        ignore = self.base / "global-ignore"
        ignore.write_text("README.md\n")
        config = self.base / "gitconfig"
        config.write_text(f"[core]\n excludesFile = {ignore}\n hooksPath = {template / 'hooks'}\n"
                          f"[init]\n templateDir = {template}\n")
        env = clean_env() | {"GIT_TEMPLATE_DIR": str(template), "GIT_CONFIG_GLOBAL": str(config)}
        self.assert_success(self.export(env=env))
        release = self.base / "release"
        self.assertFalse((release / ".git/private-note").exists())
        self.assertNotIn(b"credential", (release / ".git/config").read_bytes())
        self.assertFalse(marker.exists())
        self.assertIn(b"README.md\0", self.git("ls-files", "-z", cwd=release))

    def test_explicit_github_author_is_kept_without_ambient_override(self):
        name = "fixture-author"
        email = "12345+fixture-author" + "@" + "users.noreply.github.com"
        env = clean_env() | {"GIT_AUTHOR_NAME": "Ambient fixture",
                             "GIT_AUTHOR_EMAIL": "ambient@example.invalid"}
        self.assert_success(self.export("--author-name", name, "--author-email", email, env=env))
        release = self.base / "release"
        identities = self.git("log", "--format=%an <%ae>%n%cn <%ce>", cwd=release).decode().strip().splitlines()
        self.assertEqual(identities, [f"{name} <{email}>"] * 2)
        self.assert_success(self.command("check-public-tree.py", "--root", release, "--history"))

    def test_incomplete_explicit_author_is_rejected_before_export(self):
        result = self.export("--author-name", "Fixture author")
        self.assertEqual(result.returncode, 2)
        self.assertFalse((self.base / "release").exists())

    def test_deliberately_tracked_ignored_files_and_modes_survive(self):
        (self.source / ".gitignore").write_text("README.md\nignored-scratch\n")
        (self.source / "ignored-scratch").write_text("Not part of release")
        (self.source / "README.md").write_text("Reviewed staged update\n")
        self.git("add", ".gitignore", "README.md")
        (self.source / "README.md").chmod(0o755)
        self.git("update-index", "--chmod=+x", "README.md")
        # The reviewed index defines the executable mode in the release.
        self.assert_success(self.export())
        release = self.base / "release"
        self.assertFalse((release / "ignored-scratch").exists())
        self.assertEqual((release / "README.md").read_text(), "Reviewed staged update\n")
        self.assertTrue((release / "README.md").stat().st_mode & 0o111)
        self.assertEqual(self.git("ls-files", "--stage", "-z"),
                         self.git("ls-files", "--stage", "-z", cwd=release))

    def test_unstaged_or_untracked_work_is_rejected_before_export(self):
        (self.source / "README.md").write_text("Not reviewed\n")
        self.assertNotEqual(self.export().returncode, 0)
        self.assertFalse((self.base / "release").exists())
        self.git("checkout", "--", "README.md")
        (self.source / "not-reviewed.txt").write_text("Not reviewed\n")
        self.assertNotEqual(self.export().returncode, 0)
        self.assertFalse((self.base / "release").exists())

    def test_private_filename_is_rejected_without_echoing_its_value(self):
        private = "fixture-private" + "@" + "example.net"
        (self.source / (private + ".txt")).write_text("Public contents")
        self.git("add", "--all")
        denylist = self.base / "denylist.txt"
        denylist.write_text(private + "\n")
        for result in (self.command("check-public-tree.py", "--denylist", denylist),
                       self.export("--denylist", denylist)):
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(private, result.stdout + result.stderr)

    def test_annotated_tag_messages_and_tagger_identities_are_checked(self):
        private = "fixture-private" + "@" + "example.net"
        denylist = self.base / "denylist.txt"
        denylist.write_text(private + "\n")
        self.git("tag", "-a", "message-check", "-m", private)
        result = self.command("check-public-tree.py", "--history", "--denylist", denylist)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(private, result.stdout + result.stderr)
        self.git("tag", "-d", "message-check")
        self.git("tag", "-a", "tagger-check", "-m", "Public message",
                 env=clean_env() | {"GIT_COMMITTER_EMAIL": private})
        result = self.command("check-public-tree.py", "--history", "--denylist", denylist)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(private, result.stdout + result.stderr)

    def test_all_historical_paths_are_checked_even_for_reused_blobs(self):
        # rev-list --objects reports one name per blob, which need not be the
        # historical excluded name. Every tree must be checked independently.
        (self.source / "accounts.txt").write_text("Same public contents\n")
        self.commit()
        self.git("mv", "accounts.txt", "public-notes.txt")
        self.commit()
        self.assert_success(self.command("check-public-tree.py"))
        result = self.command("check-public-tree.py", "--history")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("history:accounts.txt", result.stdout)

    def test_index_scan_reads_reviewed_blobs_and_rejects_symlinks(self):
        private = "fixture-private" + "@" + "example.net"
        (self.source / "README.md").write_text(private)
        self.assert_success(self.command("check-public-tree.py", "--index"))
        self.assertNotEqual(self.command("check-public-tree.py").returncode, 0)
        self.git("checkout", "--", "README.md")
        (self.source / "link").symlink_to("README.md")
        self.git("add", "link")
        self.assertNotEqual(self.command("check-public-tree.py", "--index").returncode, 0)
        self.assertNotEqual(self.export().returncode, 0)

    def test_utf16_identifiers_and_disguised_archives_require_review(self):
        private = "fixture-private" + "@" + "example.net"
        path = self.source / "notes.txt"
        for encoding in ("utf-16-le", "utf-16-be"):
            path.write_bytes(private.encode(encoding))
            self.git("add", "notes.txt")
            result = self.command("check-public-tree.py", "--index")
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(private, result.stdout + result.stderr)
        path.write_bytes(b"PK\x03\x04" + b"fixture archive data")
        self.git("add", "notes.txt")
        result = self.command("check-public-tree.py", "--index")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("compressed format", result.stdout)

    def test_opaque_http_credentials_and_encrypted_keys_require_review(self):
        path = self.source / "notes.txt"
        fixtures = (
            "Authorization: " + "Bearer " + "fixture" * 5,
            "Set-Cookie: " + "session=" + "fixture" * 5,
            "-----BEGIN " + "ENCRYPTED PRIVATE KEY-----",
        )
        for value in fixtures:
            path.write_text(value)
            self.git("add", "notes.txt")
            result = self.command("check-public-tree.py", "--index")
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(value, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
