#!/usr/bin/env python3
"""Read-only bbolt filename audit diagnostic; never opens Store/Open/Update.

Walk committed pages rather than scanning stale free pages. Output deliberately
omits tokens, scopes, rule fingerprints, credentials, raw names and signed URLs.
For a running DB this is best-effort: detects a changing committed txid and asks
for retry. A transaction-consistent snapshot is preferred for forensic evidence.
"""
import argparse
import base64
import hashlib
import fnmatch
import json
import datetime
import struct


def digest(*parts):
    return hashlib.sha256(b''.join(p.encode() + b'\0' for p in parts)).hexdigest()


def inspect(db_path, config_path, display):
    with open(config_path, 'r', encoding='utf-8') as stream:
        cfg = json.load(stream)['alistServer']
    # Deliberately support only literal mount /* patterns. Arbitrary regex rules
    # must be diagnosed by the Go matcher, never silently approximated here.
    patterns = [x for p in cfg.get('passwdList', []) if p.get('enable') for x in p.get('encPath', [])]
    if any(not x.startswith('/') or any(c in x for c in '?[](){}|+^$\\\\') or '*' in x.rstrip('*') for x in patterns):
        raise ValueError('unsupported rule pattern; use native matcher')
    rules = [p for p in cfg.get('passwdList', []) if p.get('enable') and any(
        fnmatch.fnmatchcase(display, prefix)
        for prefix in p.get('encPath', []))]
    rules.sort(key=lambda p: max((len(x.removesuffix('/*').removesuffix('*')) for x in p.get('encPath', [])), default=0), reverse=True)
    rule = rules[0] if rules else None
    rule_scope = digest(rule['password'], rule['encType'], rule.get('encSuffix', ''), '\0'.join(rule.get('encPath', []))) if rule else None
    basic = 'Basic ' + base64.b64encode((cfg['scanUsername'] + ':' + cfg['scanPassword']).encode()).decode()
    scopes = {'configured_basic': digest(basic, '', ''), 'empty_authorization': digest('', '', '')}
    # Configured API/JWT header is tested locally but never printed.
    if cfg.get('scanAuthHeader'):
        scopes['configured_scan_header'] = digest(cfg['scanAuthHeader'], '', '')
    with open(db_path, 'rb', buffering=0) as source:
        def read_at(offset, size):
            source.seek(offset)
            data = source.read(size)
            if len(data) != size:
                raise ValueError('truncated committed page')
            return data
        first = read_at(0, 80)
        page_size = struct.unpack_from('<I', first, 24)[0]
        if page_size < 1024 or page_size > 65536 or page_size & (page_size - 1):
            raise ValueError('invalid page size')
        def meta():
            candidates = []
            for off in [0, page_size]:
                data = read_at(off, 80)
                if struct.unpack_from('<I', data, 16)[0] != 0xED0CDAED:
                    continue
                # bbolt uses FNV-1a for meta checksum over first 56 meta bytes.
                check = 14695981039346656037
                for x in data[16:72]:
                    check = ((check ^ x) * 1099511628211) & ((1 << 64) - 1)
                if check != struct.unpack_from('<Q', data, 72)[0]:
                    continue
                candidates.append((struct.unpack_from('<Q', data, 64)[0], struct.unpack_from('<Q', data, 32)[0]))
            if not candidates:
                raise ValueError('no valid committed metadata')
            return max(candidates)
        transaction, root = meta()
        visited = set()
        def entries(page_id=None, inline=None):
            if inline is None:
                if page_id in visited:
                    raise ValueError('page cycle')
                visited.add(page_id)
                hdr = read_at(page_id * page_size, 16)
                _, flags, count, overflow = struct.unpack('<QHHI', hdr)
                data = read_at(page_id * page_size, (overflow + 1) * page_size)
            else:
                data = inline
                _, flags, count, _ = struct.unpack_from('<QHHI', data)
            if flags & 1:
                for i in range(count):
                    off = 16 + i * 16
                    child = struct.unpack_from('<Q', data, off + 8)[0]
                    yield from entries(child)
            elif flags & 2:
                for i in range(count):
                    off = 16 + i * 16
                    item_flags, pos, key_size, value_size = struct.unpack_from('<IIII', data, off)
                    start = off + pos
                    if start + key_size + value_size > len(data):
                        raise ValueError('leaf item outside page')
                    yield data[start:start + key_size], data[start + key_size:start + key_size + value_size], item_flags
            else:
                raise ValueError('unexpected committed page flags')
        bucket = None
        for key, value, flags in entries(root):
            if key == b'filename_reservations_v1':
                if not flags & 1:
                    raise ValueError('reservation is not a bucket')
                bucket = value
                break
        results = []
        if bucket:
            pgid = struct.unpack_from('<Q', bucket)[0]
            iterator = entries(pgid) if pgid else entries(inline=bucket[16:])
            for _, value, _ in iterator:
                record = json.loads(value)
                if record.get('OriginalPath') != display:
                    continue
                def safe_time(value):
                    try:
                        return datetime.datetime.fromisoformat(str(value).replace('Z', '+00:00')).isoformat()
                    except (ValueError, TypeError):
                        return None
                status = record.get('Status')
                size = record.get('CiphertextSize')
                results.append({'status': status if status in ('pending', 'complete', 'failed') else 'invalid',
                                'ciphertext_size': size if isinstance(size, int) and size >= 0 else None,
                                'created_at': safe_time(record.get('CreatedAt')), 'updated_at': safe_time(record.get('UpdatedAt')),
                                'original_path_matches': True,
                                'current_rule_matches': record.get('RuleFingerprint') == rule_scope,
                                'auth_matches': {name: record.get('AuthScope') == scope for name, scope in scopes.items()},
                                'origin_matches_config': record.get('Origin') ==
                                (('https' if cfg.get('https') else 'http') + '://' + cfg['serverHost'] + ':' + str(cfg['serverPort']))})
        if meta() != (transaction, root):
            raise ValueError('committed transaction changed during diagnostic; retry or use consistent snapshot')
        return {'read_only': True, 'consistency': 'stable_committed_txid_best_effort_live_read',
                'rule_found': rule is not None, 'matching_record_count': len(results), 'records': results}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db', required=True)
    parser.add_argument('--config', required=True)
    parser.add_argument('--display', required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(inspect(args.db, args.config, args.display), ensure_ascii=False, indent=2))
    except Exception as error:
        # Exception strings may contain untrusted config/JSON keys or file paths.
        raise SystemExit('read-only diagnostic failed: ' + type(error).__name__)
