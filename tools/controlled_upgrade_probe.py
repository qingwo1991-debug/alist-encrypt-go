#!/usr/bin/env python3
"""Bounded, read-only local upgrade checks. Never prepares or clears recycling.

Example (JWT supplied in memory via environment, never a command-line argument):
  python3 tools/controlled_upgrade_probe.py --base http://127.0.0.1:5345 \
    --config /private/restored/conf/config.json --output /private/probe.json

Search is opt-in with --search-keyword and uses configured upstream credentials,
not the local management JWT. --self-test runs only stdlib mocks, no network.
"""
import argparse
import ipaddress
import json
import os
import re
import sys
import unittest
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

TIMEOUT = 15
BODY_LIMIT = 1024 * 1024
DISCOVERY_LIMIT = 64 * 1024
# Fixed routes, methods and credential destinations: no caller-defined endpoint.
ROUTES = {
    'health': ('base', 'GET', '/health'),
    'index': ('base', 'GET', '/public/'),
    'storages': ('base', 'GET', '/enc-api/wopan/storages'),
    'quota': ('base', 'GET', '/enc-api/wopan/quota'),
    'upstream_login': ('upstream', 'POST', '/api/auth/login'),
    'search': ('base', 'POST', '/api/fs/search'),
}


class ProbeError(Exception):
    """Only fixed, secret-free codes may be passed to this exception."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def local_origin(value):
    try:
        u = urllib.parse.urlsplit(value)
        port = u.port
        if (u.scheme not in ('http', 'https') or not u.hostname or u.username
                or u.password or u.path not in ('', '/') or u.query or u.fragment
                or any(c.isspace() for c in value)):
            raise ValueError()
        host = u.hostname.lower()
        if host != 'localhost' and not ipaddress.ip_address(host).is_loopback:
            raise ValueError()
        if port is not None and not 1 <= port <= 65535:
            raise ValueError()
        authority = '[' + host + ']' if ':' in host else host
        if port is not None:
            authority += ':' + str(port)
        return u.scheme + '://' + authority
    except (ValueError, TypeError):
        raise ProbeError('loopback_origin_required') from None


def credential(value):
    return isinstance(value, str) and 0 < len(value) <= 16384 and not any(
        ord(c) < 32 or ord(c) == 127 for c in value)


def load_settings(path):
    try:
        with Path(path).open('rb') as stream:
            raw = stream.read(BODY_LIMIT + 1)
        if len(raw) > BODY_LIMIT:
            raise ValueError()
        settings = json.loads(raw)['alistServer']
        if not isinstance(settings, dict):
            raise ValueError()
        return settings
    except (OSError, ValueError, KeyError, TypeError):
        raise ProbeError('configuration_read_failed') from None


def upstream_origin(settings):
    host = settings.get('serverHost')
    port = settings.get('serverPort')
    tls = settings.get('https', False)
    if (not isinstance(host, str) or isinstance(port, bool)
            or not isinstance(port, int) or not isinstance(tls, bool)):
        raise ProbeError('upstream_configuration_invalid')
    host = host.strip('[]')
    authority = '[' + host + ']' if ':' in host else host
    return local_origin(('https' if tls else 'http') + '://' + authority + ':' + str(port))


def decode_json(raw):
    try:
        value = json.loads(raw)
        return value if isinstance(value, dict) else None
    except (ValueError, UnicodeError):
        return None


def app_code(value):
    code = value.get('code') if isinstance(value, dict) else None
    if isinstance(code, int) and not isinstance(code, bool) and 0 <= code <= 99999:
        return code
    if isinstance(code, str) and re.fullmatch(r'[0-9]{1,5}', code):
        return int(code)
    return None


def summary(response):
    # Body, headers and errors are never emitted, even for server failures.
    out = {key: response[key] for key in ('http_status', 'bytes_read', 'bounded') if key in response}
    if 'error' in response:
        out['error'] = response['error']
    code = app_code(decode_json(response.get('_body', b'')))
    if code is not None:
        out['application_code'] = code
    return out


class Probe:
    def __init__(self, base, upstream=None, opener=None):
        self.origins = {'base': local_origin(base)}
        if upstream is not None:
            self.origins['upstream'] = local_origin(upstream)
        # Explicitly disable environment proxy inheritance and redirect following.
        self.opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(self, route, *, payload=None, jwt=None, token=None, storage_id=5):
        if route not in ROUTES:
            raise ProbeError('route_not_allowed')
        destination, method, path = ROUTES[route]
        if destination not in self.origins:
            raise ProbeError('upstream_not_configured')
        if jwt is not None and (route not in ('storages', 'quota') or not credential(jwt)):
            raise ProbeError('credential_destination_denied')
        if token is not None and (route != 'search' or not credential(token)):
            raise ProbeError('credential_destination_denied')
        if payload is not None and method != 'POST':
            raise ProbeError('request_payload_denied')
        if route == 'quota':
            if not isinstance(storage_id, int) or isinstance(storage_id, bool) or storage_id <= 0:
                raise ProbeError('storage_id_invalid')
            path += '?storage_id=' + str(storage_id)
        headers = {'Accept-Encoding': 'identity'}
        if jwt is not None:
            headers['Authorizetoken'] = jwt
        if token is not None:
            headers['Authorization'] = token
        body = None
        if method == 'POST':
            body = json.dumps(payload, ensure_ascii=False).encode('utf-8')
            headers['Content-Type'] = 'application/json'
        req = urllib.request.Request(self.origins[destination] + path, data=body, headers=headers, method=method)
        limit = DISCOVERY_LIMIT if route == 'storages' else BODY_LIMIT
        try:
            try:
                res = self.opener.open(req, timeout=TIMEOUT)
            except urllib.error.HTTPError as error:
                res = error  # Status only; redirects are not followed.
            with res:
                raw = res.read(limit + 1)
                status = res.code
            return {'http_status': status, 'bytes_read': len(raw), 'bounded': len(raw) <= limit,
                    '_body': raw if len(raw) <= limit else b''}
        except (OSError, ValueError, urllib.error.URLError):
            return {'error': 'transport_failed'}


def quota_fields(response):
    value = decode_json(response.get('_body', b''))
    data = value.get('data') if isinstance(value, dict) else None
    if response.get('http_status') != 200 or app_code(value) != 0 or not isinstance(data, dict):
        return {}
    fields = {}
    for key in ('total_bytes', 'used_bytes', 'available_bytes'):
        raw = data.get(key)
        if not isinstance(raw, str) or not re.fullmatch(r'[0-9]{1,20}', raw):
            return {'quota_fields_valid': False}
        fields[key] = raw
    total, used, available = (int(fields[k]) for k in ('total_bytes', 'used_bytes', 'available_bytes'))
    if total <= 0 or used > total or available != total - used or data.get('scope') != 'personal':
        return {'quota_fields_valid': False}
    fields.update(scope='personal', quota_fields_valid=True,
                  recycle_bin_bytes_unknown=data.get('recycle_bin_bytes', 'missing') is None)
    checked = data.get('checked_at')
    if isinstance(checked, str) and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z', checked):
        fields['checked_at'] = checked
    return fields


def run_probe(args, environ=None):
    env = os.environ if environ is None else environ
    settings = load_settings(args.config)
    probe = Probe(args.base)
    report = {'schema': 1, 'timestamp_utc': datetime.now(timezone.utc).isoformat(),
              'read_only': True, 'recycle_requests_sent': 0, 'checks': {}}
    checks = report['checks']
    for route in ('health', 'index', 'storages', 'quota'):
        result = probe.request(route, storage_id=args.storage_id)
        label = route if route in ('health', 'index') else route + '_unauthenticated'
        checks[label] = summary(result)
        if route in ('storages', 'quota'):
            checks[label]['unauthenticated_rejected'] = (result.get('http_status') == 401
                or app_code(decode_json(result.get('_body', b''))) == 401)
    jwt = env.get('LOCAL_MANAGEMENT_JWT')
    if jwt:
        if not credential(jwt):
            raise ProbeError('management_environment_token_invalid')
        checks['storages_authenticated'] = summary(probe.request('storages', jwt=jwt))
        quota = probe.request('quota', jwt=jwt, storage_id=args.storage_id)
        checks['quota_authenticated'] = dict(summary(quota), **quota_fields(quota))
    else:
        checks['management_authenticated'] = {'skipped': 'LOCAL_MANAGEMENT_JWT_not_supplied'}
    if args.search_keyword is not None:
        user, password = settings.get('scanUsername'), settings.get('scanPassword')
        if not credential(user) or not credential(password):
            raise ProbeError('configured_upstream_credentials_unavailable')
        probe.origins['upstream'] = upstream_origin(settings)
        login = probe.request('upstream_login', payload={'username': user, 'password': password})
        checks['upstream_login'] = summary(login)
        value = decode_json(login.get('_body', b''))
        data = value.get('data') if isinstance(value, dict) else None
        token = data.get('token') if isinstance(data, dict) else None
        if login.get('http_status') == 200 and app_code(value) == 200 and credential(token):
            search = probe.request('search', token=token, payload={
                'parent': args.search_parent, 'keywords': args.search_keyword,
                'scope': 0, 'page': 1, 'per_page': 20, 'password': ''})
            checks['search_authenticated'] = summary(search)
        else:
            checks['search_authenticated'] = {'skipped': 'upstream_login_failed'}
    return report


class ProbeTests(unittest.TestCase):
    def test_origins_and_route_allowlist(self):
        for origin in ('http://example.com', 'http://127.0.0.1/path', 'http://user@localhost',
                       'http://127.0.0.1?token=x', 'http://127.0.0.1#x', 'http://0.0.0.0'):
            with self.assertRaises(ProbeError):
                local_origin(origin)
        for route in ('/enc-api/wopan/recycle/clear', 'prepare', 'recover', 'retry', 'delete'):
            with self.assertRaises(ProbeError):
                Probe('http://127.0.0.1:5345').request(route)
        self.assertEqual(local_origin('http://[::1]:5345'), 'http://[::1]:5345')

    def test_redirect_never_followed(self):
        self.assertIsNone(NoRedirect().redirect_request(None, None, 302, '', {}, 'https://external.invalid'))

    def test_credentials_only_reach_intended_route(self):
        class Response:
            code = 200
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, count): return b'{"code":200,"data":{}}'
        class Opener:
            requests = []
            def open(self, request, timeout):
                self.requests.append(request)
                return Response()
        opener = Opener()
        probe = Probe('http://localhost:5345', 'http://localhost:5244', opener)
        probe.request('quota', jwt='LOCAL_SECRET')
        probe.request('search', token='UPSTREAM_SECRET', payload={})
        self.assertEqual(opener.requests[0].get_header('Authorizetoken'), 'LOCAL_SECRET')
        self.assertIsNone(opener.requests[0].get_header('Authorization'))
        self.assertEqual(opener.requests[1].get_header('Authorization'), 'UPSTREAM_SECRET')
        self.assertIsNone(opener.requests[1].get_header('Authorizetoken'))
        with self.assertRaises(ProbeError): probe.request('upstream_login', jwt='LOCAL_SECRET')
        with self.assertRaises(ProbeError): probe.request('quota', token='UPSTREAM_SECRET')

    def test_actual_management_envelope_and_index_path(self):
        data = {'total_bytes': '8796093022208', 'used_bytes': '5950362078064',
                'available_bytes': '2845730944144', 'scope': 'personal',
                'recycle_bin_bytes': None, 'checked_at': '2026-10-24T00:59:00Z'}
        def response(code):
            return {'http_status': 200, '_body': json.dumps({'code': code, 'data': data}).encode()}
        result = quota_fields(response(0))
        self.assertTrue(result['quota_fields_valid'])
        self.assertTrue(result['recycle_bin_bytes_unknown'])
        self.assertEqual(result['available_bytes'], '2845730944144')
        self.assertEqual(quota_fields(response(200)), {})
        self.assertEqual(ROUTES['index'][2], '/public/')

    def test_output_drops_response_secrets_and_large_body(self):
        response = {'http_status': 403, 'bytes_read': 50, 'bounded': True,
                    '_body': b'{"code":403,"message":"SECRET","token":"SECRET"}'}
        self.assertNotIn('SECRET', json.dumps(summary(response)))
        self.assertNotIn('SECRET', json.dumps(quota_fields(response)))
        class Response:
            code = 200
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, count): return b'x' * count
        with patch('urllib.request.OpenerDirector.open', return_value=Response()):
            result = Probe('http://localhost').request('storages')
        self.assertFalse(result['bounded'])
        self.assertEqual(result['_body'], b'')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base')
    parser.add_argument('--config')
    parser.add_argument('--output')
    parser.add_argument('--storage-id', type=int, default=5)
    parser.add_argument('--search-parent', default='/')
    parser.add_argument('--search-keyword', help='Opt in to bounded read-only search; never written to report')
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ProbeTests))
        return 0 if result.wasSuccessful() else 1
    if not all((args.base, args.config, args.output)) or args.storage_id <= 0:
        parser.error('--base, --config, --output and a positive --storage-id are required')
    if (not args.search_parent.startswith('/') or len(args.search_parent) > 4096
            or (args.search_keyword is not None and (not args.search_keyword or len(args.search_keyword) > 256))):
        parser.error('search path/keyword invalid')
    try:
        # Never overwrite a config, existing receipt, symlink or other file.
        if Path(args.output).exists() or Path(args.output).is_symlink():
            raise ProbeError('report_destination_exists')
        report = run_probe(args)
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            stream.write(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    except ProbeError as error:
        print(json.dumps({'error': str(error)}), file=sys.stderr)
        return 1
    except (OSError, ValueError, TypeError):
        print('{"error":"probe_or_report_failed"}', file=sys.stderr)
        return 1
    print('{"report_written":true,"read_only":true}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
