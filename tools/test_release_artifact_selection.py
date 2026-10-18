"""Dependency-free regression for core release artifact selection."""
from pathlib import Path
import fnmatch
import unittest


class SelectionTest(unittest.TestCase):
    def test_core_downloads_are_explicit_binary_patterns(self):
        source = (Path(__file__).resolve().parents[1] / '.github/workflows/release.yml').read_text()
        section = source.split('  release-core:', 1)[1].split('  release-mobile:', 1)[0]
        downloads = section.split('uses: actions/download-artifact@v7')[1:]
        self.assertEqual(len(downloads), 2)
        patterns = []
        for download in downloads:
            block = download.split('\n      - name:', 1)[0]
            self.assertIn('pattern:', block)
            patterns.append(block.split('pattern:', 1)[1].splitlines()[0].strip())
        self.assertEqual(patterns, ['alist-encrypt-go-*', 'encrypt-tool-*'])
        for name in ('qingwo~repo~record.dockerbuild', 'performance-baselines', 'mobile-aar-arm64-v8a', 'mobile-apk-x86_64'):
            self.assertFalse(any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns))
        for platform in ('linux-amd64', 'linux-arm64', 'linux-armv7', 'darwin-amd64', 'darwin-arm64', 'windows-amd64.exe', 'windows-arm64.exe'):
            for prefix in ('alist-encrypt-go-', 'encrypt-tool-'):
                self.assertTrue(any(fnmatch.fnmatchcase(prefix + platform, pattern) for pattern in patterns))


if __name__ == '__main__':
    unittest.main()
