#!/usr/bin/env python3
"""Read-only, bounded DAV playback probes; never writes remote objects.

A deployment config may supply the local scan account for these client requests;
credentials and signed URLs are never included in the JSON output. This measures
server response/first bytes, NOT decoded frames on a phone.
"""
import argparse
import base64
import hashlib
import json
import math
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path


# Never emit XML names or text supplied by the server unless explicitly allowed.
DAV_TAGS = frozenset(('multistatus', 'response', 'href', 'propstat', 'prop',
                      'status', 'getcontentlength', 'resourcetype', 'collection',
                      'error', 'responsedescription'))
DAV_SUMMARY_CAP = 32


def dav_summary(body, expected):
    """Bounded structural diagnostics, with no hrefs, error text or property text."""
    try:
        root = ET.fromstring(body)
    except (ET.ParseError, ValueError):
        return {'xml_parse_ok': False}

    def tag_name(element):
        tag = element.tag
        if tag.startswith('{DAV:}') and tag[6:] in DAV_TAGS:
            return tag[6:]
        return 'other'

    def child_tags(element):
        # The output vocabulary and count are fixed, even for hostile tag names.
        return sorted({tag_name(child) for child in element})

    def status_code(element):
        words = (element.findtext('{DAV:}status') or '').split()
        if (len(words) >= 2 and words[0] in ('HTTP/1.0', 'HTTP/1.1', 'HTTP/2', 'HTTP/2.0', 'HTTP/3', 'HTTP/3.0')
                and re.fullmatch(r'[1-5][0-9]{2}', words[1])):
            return int(words[1])
        return None

    responses = root.findall('{DAV:}response')
    result = {'xml_parse_ok': True, 'root_tag': tag_name(root),
              'child_tags': child_tags(root),
              'responses_truncated': len(responses) > DAV_SUMMARY_CAP, 'responses': []}
    for response in responses[:DAV_SUMMARY_CAP]:
        try:
            href = response.findtext('{DAV:}href') or ''
            target_match = urllib.parse.unquote(urllib.parse.urlsplit(href).path) == expected
        except ValueError:
            target_match = False
        propstats = response.findall('{DAV:}propstat')
        item = {'target_match': target_match, 'status': status_code(response),
                'child_tags': child_tags(response),
                'propstats_truncated': len(propstats) > DAV_SUMMARY_CAP, 'propstats': []}
        for propstat in propstats[:DAV_SUMMARY_CAP]:
            prop = propstat.find('{DAV:}prop')
            length = propstat.findtext('{DAV:}prop/{DAV:}getcontentlength')
            # Bound numeric output too; arbitrary property values never survive.
            length = length.strip() if length is not None else ''
            numeric_length = int(length) if re.fullmatch(r'[0-9]{1,20}', length) else None
            item['propstats'].append({'status': status_code(propstat), 'length': numeric_length,
                                      'child_tags': child_tags(propstat),
                                      'prop_child_tags': child_tags(prop) if prop is not None else []})
        result['responses'].append(item)
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--base', default='http://127.0.0.1:5344')
    ap.add_argument('--path', required=True, help='Logical DAV object path, starting with /dav/')
    ap.add_argument('--config', help='Deployment JSON containing scanUsername/scanPassword; used only as current client Basic auth')
    ap.add_argument('--samples', type=int, default=3)
    ap.add_argument('--timeout', type=float, default=30)
    ap.add_argument('--output', required=True)
    ap.add_argument('--directory', action='store_true', help='Also read parent Depth:1 listing, bounded to 16 MiB')
    args = ap.parse_args()
    if not args.path.startswith('/dav/') or not 1 <= args.samples <= 100:
        ap.error('path must start /dav/; samples must be 1..100')
    origin = urllib.parse.urlsplit(args.base)
    if origin.scheme not in ('http', 'https') or not origin.netloc or origin.query or origin.fragment:
        ap.error('base must be an HTTP(S) origin')
    headers = {'Accept-Encoding': 'identity'}
    if args.config:
        c = json.loads(Path(args.config).read_text())['alistServer']
        user, password = c.get('scanUsername', ''), c.get('scanPassword', '')
        if not user or not password:
            ap.error('config does not contain usable scan account credentials')
        headers['Authorization'] = 'Basic ' + base64.b64encode(f'{user}:{password}'.encode()).decode()

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, hdrs, newurl):
            return None

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    records = []

    def request(label, method, path, extra=None, cap=65536):
        h = dict(headers)
        h.update(extra or {})
        url = args.base.rstrip('/') + urllib.parse.quote(path, safe='/@.~-')
        req = urllib.request.Request(url, method=method, headers=h)
        start = time.monotonic()
        rec = {'label': label, 'method': method, 'path': path}
        body = b''
        try:
            try:
                response = opener.open(req, timeout=args.timeout)
            except urllib.error.HTTPError as exc:
                response = exc
            with response:
                rec['status'] = response.code
                rec['headers_ms'] = round((time.monotonic() - start) * 1000, 3)
                rec['headers'] = {key: response.headers[key] for key in (
                    'Content-Length', 'Content-Range', 'Content-Type', 'X-Alist-Encrypt-Cache'
                ) if key in response.headers}
                body = response.read(cap + 1)
                rec['over_body_budget'] = len(body) > cap
                body = body[:cap]
                rec['bytes_read'] = len(body)
                rec['body_sha256'] = hashlib.sha256(body).hexdigest()
                rec['bounded_body_ms'] = round((time.monotonic() - start) * 1000, 3)
        except Exception as exc:
            # Exception strings can contain URLs/headers; publish only their type.
            rec['error_type'] = type(exc).__name__
        records.append(rec)
        return rec, body

    def dav_length(body, expected):
        try:
            root = ET.fromstring(body)
            matches = []
            for response in root.findall('{DAV:}response'):
                href = response.findtext('{DAV:}href', '')
                if urllib.parse.unquote(urllib.parse.urlsplit(href).path) != expected:
                    continue
                for propstat in response.findall('{DAV:}propstat'):
                    status = propstat.findtext('{DAV:}status', '').split()
                    length = propstat.findtext('{DAV:}prop/{DAV:}getcontentlength')
                    if len(status) >= 2 and status[1] == '200' and length is not None:
                        matches.append(int(length))
            return matches
        except (ET.ParseError, ValueError):
            return []

    total = None
    for sample in range(args.samples):
        rec, body = request(f'propfind_{sample}', 'PROPFIND', args.path, {'Depth': '0'})
        rec['dav_lengths'] = dav_length(body, args.path)
        if len(rec['dav_lengths']) != 1 or rec['dav_lengths'][0] < 0:
            rec['dav_summary'] = dav_summary(body, args.path)
        request(f'head_{sample}', 'HEAD', args.path, cap=0)
        rec, body = request(f'prefix_{sample}', 'GET', args.path, {'Range': 'bytes=0-1023'}, cap=1024)
        match = re.fullmatch(r'bytes 0-(\d+)/(\d+)', rec.get('headers', {}).get('Content-Range', ''))
        if rec.get('status') == 206 and match:
            total = int(match[2])
    if total:
        for label, range_value in (
            ('middle', f'bytes={total//2}-{min(total-1,total//2+1023)}'),
            ('tail', 'bytes=-1024'),
            ('eof_416', f'bytes={total}-'),
        ):
            request(label, 'GET', args.path, {'Range': range_value}, cap=4096)
    if args.directory:
        parent = args.path.rsplit('/', 1)[0]
        for path in (parent, parent + '/'):
            rec, body = request('directory', 'PROPFIND', path, {'Depth': '1'}, cap=16 * 1024 * 1024)
            rec['target_dav_lengths'] = dav_length(body, args.path)
            if len(rec['target_dav_lengths']) != 1 or rec['target_dav_lengths'][0] < 0:
                rec['dav_summary'] = dav_summary(body, args.path)

    groups = {}
    for prefix in ('propfind', 'head', 'prefix'):
        samples = sorted(r['bounded_body_ms'] for r in records if r['label'].startswith(prefix + '_') and 'bounded_body_ms' in r)
        if samples:
            groups[prefix] = {'n': len(samples), 'p50_ms': samples[math.ceil(.5*len(samples))-1], 'p95_ms': samples[math.ceil(.95*len(samples))-1]}
    report = {
        'schema': 1, 'timestamp_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'base': args.base, 'path': args.path, 'client_auth': 'configured_scan_account_as_basic_client' if args.config else 'anonymous',
        'cold_state': 'not_forced; sequential requests may warm caches',
        'device_frames_measured': False, 'range_total': total,
        'timings': groups, 'records': records,
        'limits': 'Read-only bounded bodies; hashes compare repeatability, not correctness without a reference plaintext. Timings are headers/body retrieval, not video frames.',
    }
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'output': str(out), 'range_total': total, 'timings': groups,
                      'results': [{k: v for k, v in r.items() if k in ('label', 'status', 'dav_lengths', 'target_dav_lengths', 'dav_summary', 'error_type')} for r in records]}, ensure_ascii=False))


if __name__ == '__main__':
    main()
