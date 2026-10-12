#!/usr/bin/env python3
"""Offline fingerprint/mirror/preflight regressions (stdlib only)."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import verify_source_overlay as overlay


class SourceOverlayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.upstream = self.root / "upstream"
        self.patches = self.root / "patches"
        self.upstream.mkdir()
        self.patches.mkdir()
        self.old = "pkg/utils/original.go"
        self.new = "internal/net/local.go"
        self.manifest = {"version": 1, "upstream_tag": "v1", "upstream_commit": "a" * 40,
                         "files": {self.old: hashlib.sha256(b"pristine").hexdigest(), self.new: None}}
        self.put(self.upstream, self.old, b"pristine")
        self.put(self.patches, self.old, b"patched")
        self.put(self.patches, self.new, b"local")

    @staticmethod
    def put(root, name, body):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)

    def apply(self):
        overlay.apply_overlay(self.manifest, self.upstream, self.patches, "v1", "a" * 40)

    def test_pristine_and_absent_pass_then_apply(self):
        self.apply()
        self.assertEqual((self.upstream / self.old).read_bytes(), b"patched")
        self.assertEqual((self.upstream / self.new).read_bytes(), b"local")
        with self.assertRaises(overlay.OverlayError):
            self.apply()  # Patched is deliberately NOT accepted as pristine.

    def test_changed_original_refused_without_overwrite(self):
        self.put(self.upstream, self.old, b"upstream changed")
        with self.assertRaises(overlay.OverlayError):
            self.apply()
        self.assertEqual((self.upstream / self.old).read_bytes(), b"upstream changed")
        self.assertFalse((self.upstream / self.new).exists())

    def test_new_file_collision_preflight_no_partial_apply(self):
        self.put(self.upstream, self.new, b"new upstream file")
        with self.assertRaises(overlay.OverlayError):
            self.apply()
        self.assertEqual((self.upstream / self.old).read_bytes(), b"pristine")
        self.assertEqual((self.upstream / self.new).read_bytes(), b"new upstream file")

    def test_missing_patch_preflight_no_partial_apply(self):
        (self.patches / self.new).unlink()
        with self.assertRaises(overlay.OverlayError):
            self.apply()
        self.assertEqual((self.upstream / self.old).read_bytes(), b"pristine")

    def test_wrong_pin_and_retargeted_tag_fail(self):
        for tag, commit in [("v2", "a" * 40), ("v1", "b" * 40)]:
            with self.subTest(tag=tag, commit=commit), self.assertRaises(overlay.OverlayError):
                overlay.verify_pristine(self.manifest, self.upstream, tag, commit)
        self.assertEqual((self.upstream / self.old).read_bytes(), b"pristine")

    def test_mirror_drift_fail_and_equal_pass(self):
        for name in self.manifest["files"]:
            self.put(self.root, name, b"patched")
            self.put(self.root / "src", name, b"patched")
        overlay.check_mirrors(self.manifest, self.root)
        self.put(self.root / "src", self.old, b"local edit")
        with self.assertRaises(overlay.OverlayError):
            overlay.check_mirrors(self.manifest, self.root)

    def test_symlink_rejected(self):
        (self.upstream / self.old).unlink()
        (self.upstream / self.old).symlink_to(self.patches / self.old)
        with self.assertRaises(overlay.OverlayError):
            self.apply()

    def test_manifest_path_and_list_validation(self):
        manifest = self.root / "manifest.json"
        names = self.root / "files.txt"
        manifest.write_text(json.dumps(self.manifest))
        names.write_text("\n".join(self.manifest["files"]) + "\n")
        overlay.load_manifest(manifest, names)
        names.write_text(self.old + "\n")
        with self.assertRaises(overlay.OverlayError):
            overlay.load_manifest(manifest, names)
        self.manifest["files"] = {"internal/../outside.go": None}
        names.write_text("internal/../outside.go\n")
        manifest.write_text(json.dumps(self.manifest))
        with self.assertRaises(overlay.OverlayError):
            overlay.load_manifest(manifest, names)


if __name__ == "__main__":
    unittest.main()
