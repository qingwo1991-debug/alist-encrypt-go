#!/usr/bin/env python3
"""Offline manual sync safety regressions (stdlib only)."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

import sync_source_overlay as sync
import verify_source_overlay as overlay


class SyncSourceOverlayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.names = ["internal/net/first.go", "internal/net/second.go"]
        self.manifest = self.root / "manifest.json"
        self.file_list = self.root / "files.txt"
        self.data = {"version": 1, "upstream_tag": "v1", "upstream_commit": "a" * 40,
                     "files": {self.names[0]: "b" * 64, self.names[1]: None}}
        self.manifest.write_text(json.dumps(self.data))
        self.file_list.write_text("\n".join(self.names) + "\n")
        (self.root / "UPSTREAM_VERSION").write_text("v1\n")
        for name in self.names:
            self.put(name, b"reviewed actual")
            self.put("src/" + name, b"previous mirror")
        self.original_manifest = self.manifest.read_bytes()
        self.original_list = self.file_list.read_bytes()

    def put(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    def run_sync(self, apply=True):
        return sync.sync(self.root, self.manifest, self.file_list, apply=apply)

    def assert_first_unchanged(self):
        self.assertEqual((self.root / "src" / self.names[0]).read_bytes(), b"previous mirror")

    def test_preview_is_read_only(self):
        self.assertEqual(self.run_sync(apply=False), self.names)
        self.assert_first_unchanged()

    def test_apply_listed_only_preserves_fingerprints_and_mode(self):
        self.put("src/internal/net/unlisted.go", b"unlisted mirror")
        self.put("internal/net/unlisted.go", b"unlisted actual")
        target = self.root / "src" / self.names[0]
        target.chmod(0o640)
        self.assertEqual(self.run_sync(), self.names)
        for name in self.names:
            self.assertEqual((self.root / "src" / name).read_bytes(), b"reviewed actual")
        self.assertEqual(target.stat().st_mode & 0o777, 0o640)
        self.assertEqual((self.root / "src/internal/net/unlisted.go").read_bytes(), b"unlisted mirror")
        self.assertEqual(self.manifest.read_bytes(), self.original_manifest)
        self.assertEqual(self.file_list.read_bytes(), self.original_list)
        self.assertEqual(self.run_sync(), [])

    def test_hardlinked_peer_not_overwritten(self):
        peer = self.root / "peer.go"
        os.link(self.root / "src" / self.names[0], peer)
        self.run_sync()
        self.assertEqual(peer.read_bytes(), b"previous mirror")

    def test_wrong_upstream_version_no_partial_write(self):
        (self.root / "UPSTREAM_VERSION").write_text("v2")
        with self.assertRaises(overlay.OverlayError):
            self.run_sync()
        self.assert_first_unchanged()

    def test_manifest_list_mismatch_no_partial_write(self):
        self.file_list.write_text(self.names[0] + "\n")
        with self.assertRaises(overlay.OverlayError):
            self.run_sync()
        self.assert_first_unchanged()

    def test_unsafe_path_no_partial_write(self):
        name = "internal/../escape.go"
        self.data["files"][name] = None
        self.manifest.write_text(json.dumps(self.data))
        self.file_list.write_text("\n".join(self.data["files"]) + "\n")
        with self.assertRaises(overlay.OverlayError):
            self.run_sync()
        self.assert_first_unchanged()

    def test_late_missing_or_nonregular_source_and_target_no_partial_write(self):
        for side in ("", "src/"):
            for kind in ("missing", "directory", "fifo", "symlink"):
                with self.subTest(side=side, kind=kind):
                    path = self.root / (side + self.names[1])
                    path.unlink()
                    if kind == "directory":
                        path.mkdir()
                    elif kind == "fifo":
                        os.mkfifo(path)
                    elif kind == "symlink":
                        path.symlink_to(self.root / self.names[0])
                    with self.assertRaises((overlay.OverlayError, OSError)):
                        self.run_sync()
                    self.assert_first_unchanged()
                    if kind == "directory":
                        path.rmdir()
                    elif kind != "missing":
                        path.unlink()
                    path.write_bytes(b"reviewed actual" if not side else b"previous mirror")

    def test_symlinked_src_root_no_partial_write(self):
        (self.root / "src").rename(self.root / "real-src")
        (self.root / "src").symlink_to(self.root / "real-src", target_is_directory=True)
        with self.assertRaises(overlay.OverlayError):
            self.run_sync()
        self.assert_first_unchanged()

    def test_control_files_must_be_regular_and_nonsymlink(self):
        for path in (self.manifest, self.file_list, self.root / "UPSTREAM_VERSION"):
            with self.subTest(path=path):
                body = path.read_bytes()
                peer = path.with_suffix(".peer")
                peer.write_bytes(body)
                path.unlink()
                path.symlink_to(peer)
                with self.assertRaises(overlay.OverlayError):
                    self.run_sync()
                self.assert_first_unchanged()
                path.unlink()
                path.write_bytes(body)

    def test_cli_default_preview_apply_and_failure_status(self):
        args = ["--root", str(self.root), "--manifest", str(self.manifest),
                "--file-list", str(self.file_list)]
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(sync.main(args), 0)
        self.assertIn("Would sync:", out.getvalue())
        self.assert_first_unchanged()
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(sync.main(args + ["--apply"]), 0)
        (self.root / "UPSTREAM_VERSION").write_text("v2")
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(sync.main(args + ["--apply"]), 1)
        self.assertIn("Source overlay sync failed:", err.getvalue())


if __name__ == "__main__":
    unittest.main()
