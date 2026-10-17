"""Network-free unit contracts for the read-only local playback probe."""
import contextlib
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).with_name('local_playback_probe.py')
spec = importlib.util.spec_from_file_location('local_playback_probe', SCRIPT)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class Response(io.BytesIO):
    def __init__(self, code, data, headers=None):
        super().__init__(data)
        self.code = code
        self.headers = headers or {}


class FakeOpener:
    def __init__(self):
        self.calls = []

    def open(self, request, timeout):
        self.calls.append(request)
        method = request.get_method()
        if method == 'PROPFIND':
            return Response(207, b'<d:multistatus xmlns:d="DAV:"><d:response><d:href>/dav/example.mp4</d:href><d:propstat><d:prop><d:getcontentlength>4096</d:getcontentlength></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>')
        if method == 'HEAD':
            return Response(200, b'', {'Content-Length': '4096'})
        range_value = request.headers['Range']
        if range_value == 'bytes=4096-':
            return Response(416, b'', {'Content-Range': 'bytes */4096'})
        start = 0
        if range_value.startswith('bytes=-'):
            start = 3072
        elif range_value != 'bytes=0-1023':
            start = 2048
        return Response(206, b'x' * 1024, {'Content-Range': f'bytes {start}-{start+1023}/4096', 'Content-Length': '1024'})


class ProbeContracts(unittest.TestCase):
    def test_read_only_bounded_report_does_not_expose_credentials(self):
        opener = FakeOpener()
        with tempfile.TemporaryDirectory() as temp:
            config = Path(temp) / 'config.json'
            config.write_text(json.dumps({'alistServer': {'scanUsername': 'fixture-user', 'scanPassword': 'fixture-secret'}}))
            output = Path(temp) / 'result.json'
            argv = ['probe', '--path', '/dav/example.mp4', '--samples', '2', '--config', str(config), '--output', str(output)]
            with patch.object(sys, 'argv', argv), patch.object(probe.urllib.request, 'build_opener', return_value=opener), contextlib.redirect_stdout(io.StringIO()):
                probe.main()
            report = json.loads(output.read_text())
            self.assertEqual(report['range_total'], 4096)
            self.assertFalse(report['device_frames_measured'])
            self.assertEqual(report['timings']['prefix']['n'], 2)
            self.assertEqual([r['status'] for r in report['records'][-3:]], [206, 206, 416])
            self.assertEqual(report['records'][0]['dav_lengths'], [4096])
            self.assertNotIn('fixture-secret', output.read_text())
            self.assertNotIn('Authorization', output.read_text())
            self.assertTrue(all(r.get_method() in ('PROPFIND', 'HEAD', 'GET') for r in opener.calls))
            self.assertTrue(all(r.headers.get('Authorization', '').startswith('Basic ') for r in opener.calls))

    def test_reject_invalid_samples_and_path(self):
        for args in (['--path', '/notdav'], ['--path', '/dav/x', '--samples', '0']):
            result = subprocess.run([sys.executable, str(SCRIPT), *args, '--output', '/unused'], capture_output=True)
            self.assertEqual(result.returncode, 2)


if __name__ == '__main__':
    unittest.main()
