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

    def run_xml_probe(self, xml):
        opener = FakeOpener()
        original_open = opener.open

        def open_response(request, timeout):
            if request.get_method() == 'PROPFIND':
                opener.calls.append(request)
                return Response(207, xml)
            return original_open(request, timeout)

        opener.open = open_response
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'result.json'
            argv = ['probe', '--path', '/dav/example.mp4', '--samples', '1',
                    '--directory', '--output', str(output)]
            stdout = io.StringIO()
            with patch.object(sys, 'argv', argv), patch.object(probe.urllib.request, 'build_opener', return_value=opener), contextlib.redirect_stdout(stdout):
                probe.main()
            text = output.read_text()
            return json.loads(text), text + stdout.getvalue(), json.loads(stdout.getvalue())

    @staticmethod
    def multistatus(href='/dav/example.mp4', status='200 OK', length='4096', extra=''):
        return (f'<d:multistatus xmlns:d="DAV:"><d:response><d:href>{href}</d:href>'
                f'<d:propstat><d:prop><d:getcontentlength>{length}</d:getcontentlength>'
                f'{extra}</d:prop><d:status>HTTP/1.1 {status}</d:status></d:propstat>'
                '</d:response></d:multistatus>').encode()

    def test_known_length_preserves_file_and_directory_contract(self):
        report, _, stdout = self.run_xml_probe(self.multistatus())
        records = [r for r in report['records'] if r['method'] == 'PROPFIND']
        self.assertEqual(len(records), 3)
        for rec in records:
            key = 'target_dav_lengths' if rec['label'] == 'directory' else 'dav_lengths'
            self.assertEqual(rec[key], [4096])
            self.assertNotIn('dav_summary', rec)
        self.assertTrue(all('dav_summary' not in r for r in stdout['results']))

    def test_unavailable_length_404_has_safe_structure_including_directory(self):
        xml = self.multistatus(status='404 secret-reason', length='',
                               extra='<d:error>secret-error</d:error><private-secret>secret-property</private-secret>')
        report, output, stdout = self.run_xml_probe(xml)
        records = [r for r in report['records'] if r['method'] == 'PROPFIND']
        for rec in records:
            key = 'target_dav_lengths' if rec['label'] == 'directory' else 'dav_lengths'
            self.assertEqual(rec[key], [])
            summary = rec['dav_summary']
            self.assertTrue(summary['xml_parse_ok'])
            response = summary['responses'][0]
            self.assertTrue(response['target_match'])
            self.assertEqual(response['propstats'][0]['status'], 404)
            self.assertIsNone(response['propstats'][0]['length'])
            self.assertEqual(response['propstats'][0]['prop_child_tags'], ['error', 'getcontentlength', 'other'])
        for secret in ('secret-reason', 'secret-error', 'private-secret', 'secret-property'):
            self.assertNotIn(secret, output)
        self.assertEqual(stdout['results'][0]['dav_summary'], records[0]['dav_summary'])

    def test_mismatching_signed_href_only_emits_match_boolean(self):
        href = 'https://secret-user:secret-password@secret-host/dav/secret-other.mp4?sign=secret-sign&amp;token=secret-token'
        report, output, _ = self.run_xml_probe(self.multistatus(href=href))
        summary = report['records'][0]['dav_summary']
        self.assertTrue(summary['xml_parse_ok'])
        response = summary['responses'][0]
        self.assertFalse(response['target_match'])
        self.assertEqual(response['propstats'][0]['status'], 200)
        self.assertEqual(response['propstats'][0]['length'], 4096)
        for secret in ('secret-user', 'secret-password', 'secret-host', 'secret-other', 'secret-sign', 'secret-token'):
            self.assertNotIn(secret, output)

    def test_malformed_xml_never_emits_raw_text(self):
        report, output, _ = self.run_xml_probe(b'<d:multistatus>secret-malformed https://private.invalid/?token=secret-token')
        for rec in report['records']:
            if rec['method'] == 'PROPFIND':
                self.assertEqual(rec['dav_summary'], {'xml_parse_ok': False})
        for secret in ('secret-malformed', 'private.invalid', 'secret-token'):
            self.assertNotIn(secret, output)

    def test_summary_caps_counts_and_uses_fixed_vocabulary(self):
        propstat = '<d:propstat><d:status>secret-status</d:status><d:prop><d:getcontentlength>secret-length</d:getcontentlength><secret-tag/></d:prop></d:propstat>'
        response = '<d:response><d:href>http://[secret-invalid</d:href>' + propstat * 33 + '</d:response>'
        xml = ('<d:multistatus xmlns:d="DAV:">' + response * 33 + '</d:multistatus>').encode()
        summary = probe.dav_summary(xml, '/dav/example.mp4')
        self.assertTrue(summary['responses_truncated'])
        self.assertEqual(len(summary['responses']), 32)
        for item in summary['responses']:
            self.assertFalse(item['target_match'])
            self.assertTrue(item['propstats_truncated'])
            self.assertEqual(len(item['propstats']), 32)
            self.assertIsNone(item['propstats'][0]['status'])
            self.assertIsNone(item['propstats'][0]['length'])
        self.assertNotIn('secret', json.dumps(summary))

    def test_reject_invalid_samples_and_path(self):
        for args in (['--path', '/notdav'], ['--path', '/dav/x', '--samples', '0']):
            result = subprocess.run([sys.executable, str(SCRIPT), *args, '--output', '/unused'], capture_output=True)
            self.assertEqual(result.returncode, 2)


if __name__ == '__main__':
    unittest.main()
