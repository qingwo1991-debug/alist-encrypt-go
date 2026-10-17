#!/usr/bin/env python3
"""Cheap dependency-free tests for inventory coverage and fail-closed drift."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('inventory', Path(__file__).with_name('check_driver_inventory.py'))
inv = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inv)
REPO = Path(__file__).resolve().parents[1]


class InventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.current = inv.snapshot(REPO)
        cls.data = json.loads((REPO / inv.INVENTORY).read_text())

    def check(self, data=None, snapshot=None):
        with patch.object(inv, 'snapshot', return_value=snapshot or self.current):
            return inv.check(REPO, data or self.data)

    def test_checked_inventory_matches_actual_sources(self):
        self.assertEqual(inv.check(REPO, self.data), [])
        self.assertEqual(self.current['registered_package_count'], 81)
        self.assertEqual(self.current['actual_registered_count'], 88)
        self.assertEqual(self.current['unregistered_directories'], ['base', 'template'])
        self.assertEqual(sum(row['review_status'] == 'reviewed-static' for row in self.data['drivers'].values()), 22)
        self.assertTrue(all(row['cancel_proof'] is False for row in self.data['drivers'].values()))

    def test_added_driver_is_not_silently_omitted(self):
        changed = copy.deepcopy(self.current)
        changed['drivers']['new_driver'] = copy.deepcopy(changed['drivers']['s3'])
        self.assertTrue(any('added=' in error and 'new_driver' in error for error in self.check(snapshot=changed)))

    def test_removed_driver_is_not_silently_kept(self):
        changed = copy.deepcopy(self.current)
        del changed['drivers']['wopan']
        self.assertTrue(any('removed=' in error and 'wopan' in error for error in self.check(snapshot=changed)))

    def test_source_and_src_change_require_updated_review(self):
        for field in ('source_sha256', 'src_sha256'):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.current)
                changed['drivers']['s3'][field]['drivers/s3/driver.go'] = '0' * 64
                self.assertTrue(any('s3.' + field in error for error in self.check(snapshot=changed)))

    def test_version_module_overlay_and_sdk_change_require_review(self):
        for field in ('upstream_tag', 'overlay_upstream_commit', 'support_sha256', 'local_sdk_sha256', 'registry_sha256'):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.current)
                changed[field] = 'changed'
                self.assertTrue(any(field in error for error in self.check(snapshot=changed)))

    def test_every_operation_required_and_no_green_promotion(self):
        changed = copy.deepcopy(self.data)
        del changed['drivers']['s3']['operations']['Refresh']
        self.assertTrue(any('operation coverage' in error for error in self.check(data=changed)))
        changed = copy.deepcopy(self.data)
        changed['drivers']['s3']['cancel_proof'] = True
        self.assertTrue(any('cancel proof' in error for error in self.check(data=changed)))

    def test_review_evidence_must_resolve(self):
        changed = copy.deepcopy(self.data)
        changed['drivers']['s3']['operations']['List']['evidence'] = ['mobile/openlist-lib/drivers/s3/driver.go:999999']
        self.assertTrue(any('out-of-range evidence' in error for error in self.check(data=changed)))

    def test_registration_parser_counts_variants_and_rejects_unknown_shapes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'drivers/demo').mkdir(parents=True)
            (root / 'drivers/all.go').write_text('package drivers\nimport _ "' + inv.PREFIX + 'demo"\n')
            meta = root / 'drivers/demo/meta.go'
            meta.write_text('Name: "One"\nName: "Two"\nop.RegisterDriver(func(){})\nop.RegisterDriver(func(){})\n')
            self.assertEqual(inv.registrations(root)['demo']['registration_calls'], 2)
            meta.write_text('Name: unknown\nop.RegisterDriver(func(){})\n')
            with self.assertRaisesRegex(ValueError, 'manual parser/review'):
                inv.registrations(root)

    def test_scaffold_is_structurally_valid_without_claiming_review(self):
        self.assertEqual(inv.check(REPO, inv.draft(REPO)), [])

    def test_scaffold_never_claims_review_or_support(self):
        data = inv.draft(REPO)
        for row in data['drivers'].values():
            self.assertEqual(row['review_status'], 'unchecked')
            self.assertFalse(row['cancel_proof'])
            self.assertEqual(row['support_status'], 'unsupported-needs-review')


if __name__ == '__main__':
    unittest.main()
