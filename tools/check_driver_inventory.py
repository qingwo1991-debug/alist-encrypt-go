#!/usr/bin/env python3
"""Offline static inventory drift gate; never infers transport capabilities.

--draft emits an UNCHECKED scaffold, never updates a reviewed inventory in place.
No Go imports, package downloads, network access, or credentials are used.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

OPERATIONS = ('Init', 'List', 'Link', 'Read', 'Put', 'Refresh', 'Drop')
PREFIX = 'github.com/OpenListTeam/OpenList/v4/drivers/'
INVENTORY = 'docs/driver_transport_inventory.json'
SUPPORT = ('UPSTREAM_VERSION', 'go.mod', 'go.sum', 'internal/driver',
           'internal/op/driver.go', 'internal/model', 'internal/net', 'internal/stream', 'internal/op/storage.go',
           'internal/op/readiness.go', 'pkg/utils', 'pkg/stream', 'pkg/cron', 'drivers/base', 'scripts',
           'src/go.mod', 'src/go.sum', 'src/internal/driver',
           'src/internal/op/driver.go', 'src/internal/model', 'src/internal/net', 'src/internal/stream',
           'src/pkg/utils', 'src/pkg/stream', 'src/pkg/cron', 'src/drivers/base')


def fingerprint_files(root, paths):
    result = {}
    for path in paths:
        if path.is_symlink():
            raise ValueError('symlink cannot be reviewed: ' + str(path))
        if path.is_file() and '__pycache__' not in path.parts and path.suffix != '.pyc':
            result[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return dict(sorted(result.items()))


def tree_files(path):
    return sorted(p for p in path.rglob('*') if p.is_file() or p.is_symlink()) if path.is_dir() else [path]


def registrations(root):
    """Narrow fail-closed parser for this fixed literal registry, not a Go interpreter."""
    drivers = root / 'drivers'
    all_source = (drivers / 'all.go').read_text()
    packages = re.findall(r'_\s+"' + re.escape(PREFIX) + r'([^"/]+)"', all_source)
    if not packages or len(packages) != len(set(packages)):
        raise ValueError('unsupported/duplicate drivers/all.go imports; manual registry review required')
    rows = {}
    for name in sorted(packages):
        folder = drivers / name
        sources = [(p, p.read_text()) for p in sorted(folder.glob('*.go')) if not p.name.endswith('_test.go')]
        calls = sum(len(re.findall(r'\bop\.RegisterDriver\s*\(', text)) for _, text in sources)
        meta = (folder / 'meta.go').read_text()
        names = re.findall(r'\bName:\s*"([^"\n]+)"', meta)
        if not calls or calls != len(names) or len(names) != len(set(names)):
            raise ValueError(f'{name}: registry not literal one-name-per-constructor; manual parser/review update required')
        rows[name] = {'registered_names': names, 'registration_calls': calls,
                      'registration_evidence': f'drivers/{name}/meta.go',
                      'source_sha256': fingerprint_files(root, tree_files(folder)),
                      'src_sha256': fingerprint_files(root, tree_files(root / 'src/drivers' / name))}
    all_names = [name for row in rows.values() for name in row['registered_names']]
    if len(all_names) != len(set(all_names)):
        raise ValueError('duplicate global registration name; manual registry review required')
    return rows


def snapshot(repo):
    root = repo / 'mobile/openlist-lib'
    rows = registrations(root)
    folders = sorted(p.name for p in (root / 'drivers').iterdir() if p.is_dir())
    overlay = json.loads((root / 'scripts/source_overlay_manifest.json').read_text())
    support = []
    for rel in SUPPORT:
        support.extend(tree_files(root / rel))
    return {'upstream_tag': (root / 'UPSTREAM_VERSION').read_text().strip(),
            'overlay_upstream_commit': overlay['upstream_commit'],
            'registered_package_count': len(rows),
            'actual_registered_count': sum(r['registration_calls'] for r in rows.values()),
            'registration_basis': 'static literal op.RegisterDriver constructors reachable via drivers/all.go; not executed runtime probe',
            'driver_directories': folders,
            'unregistered_directories': sorted(set(folders) - set(rows)),
            'registry_sha256': fingerprint_files(root, [root / 'drivers/all.go', root / 'src/drivers/all.go']),
            'support_sha256': fingerprint_files(root, support),
            'local_sdk_sha256': fingerprint_files(repo, tree_files(repo / 'shared/go-mega')),
            'drivers': rows}


def draft(repo):
    current = snapshot(repo)
    for row in current['drivers'].values():
        row.update(review_status='unchecked', transport_ownership='needs-review', transport_kinds=['unknown'],
                   cancel_proof=False, support_status='unsupported-needs-review',
                   operations={op: {'context_hooks': [], 'reason': 'Unchecked call path: unsupported until actual transport ownership, request context and lifecycle are reviewed.',
                                    'transport_ownership': 'needs-review',
                                    'unsupported_reason': 'Actual operation transport and lifecycle unchecked; no end-to-end guarantee.',
                                    'evidence': [], 'assessment': 'unchecked'} for op in OPERATIONS})
    return {'schema_version': 1, 'scope': 'P3 static preparation only; does not replace P2 or prove cancellation', **current}


def check(repo, data):
    errors = []
    current = snapshot(repo)
    if data.get('schema_version') != 1:
        errors.append('unsupported schema_version')
    for key, value in current.items():
        if key != 'drivers' and data.get(key) != value:
            errors.append(f'{key}: source/version/registry drift; updated human review required')
    old = data.get('drivers', {})
    if set(old) != set(current['drivers']):
        errors.append('driver coverage changed: added=' + str(sorted(set(current['drivers']) - set(old))) +
                      ' removed=' + str(sorted(set(old) - set(current['drivers']))))
    for package, observed in current['drivers'].items():
        row = old.get(package, {})
        for field, value in observed.items():
            if row.get(field) != value:
                errors.append(f'{package}.{field}: source/registration drift; updated review required')
        if row.get('review_status') not in ('unchecked', 'reviewed-static'):
            errors.append(f'{package}: invalid review status')
        if row.get('cancel_proof') is not False or row.get('support_status') != 'unsupported-needs-review':
            errors.append(f'{package}: this inventory cannot grant runtime support/cancel proof')
        if not row.get('transport_ownership') or not row.get('transport_kinds'):
            errors.append(f'{package}: missing transport ownership/kinds')
        ops = row.get('operations', {})
        if set(ops) != set(OPERATIONS):
            errors.append(f'{package}: missing/extra operation coverage')
        for op, detail in ops.items():
            if not detail.get('transport_ownership') or not detail.get('unsupported_reason'):
                errors.append(f'{package}.{op}: missing ownership/unsupported reason')
            if (not detail.get('reason') or not isinstance(detail.get('context_hooks'), list)
                    or not isinstance(detail.get('evidence'), list)):
                errors.append(f'{package}.{op}: missing hooks/reason/evidence')
            if row.get('review_status') == 'reviewed-static' and not detail.get('evidence'):
                errors.append(f'{package}.{op}: reviewed operation needs source evidence')
            for reference in detail.get('evidence', []):
                if not isinstance(reference, str) or not reference.startswith(('mobile/openlist-lib/', 'shared/go-mega/')) or '..' in Path(reference.split(':')[0]).parts:
                    errors.append(f'{package}.{op}: evidence outside fixed source scope')
                    continue
                match = re.fullmatch(r'([^:]+):(\d+)(?:-(\d+))?', reference)
                if not match:
                    errors.append(f'{package}.{op}: invalid source reference {reference}')
                    continue
                rel, first, last = match.groups()
                source = repo / rel
                if not source.is_file() or not (1 <= int(first) <= int(last or first) <= len(source.read_text().splitlines())):
                    errors.append(f'{package}.{op}: missing/out-of-range evidence {reference}')
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo-root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--inventory', type=Path)
    parser.add_argument('--draft', action='store_true', help='print unchecked scaffold; does not approve reviews')
    args = parser.parse_args()
    try:
        if args.draft:
            print(json.dumps(draft(args.repo_root), indent=2, ensure_ascii=False))
            return 0
        path = args.inventory or args.repo_root / INVENTORY
        data = json.loads(path.read_text())
        errors = check(args.repo_root, data)
        if errors:
            print('\n'.join(errors), file=sys.stderr)
            return 1
        reviewed = sum(r['review_status'] == 'reviewed-static' for r in data['drivers'].values())
        print(f"Inventory fresh: {data['actual_registered_count']} registrations / {data['registered_package_count']} packages; {reviewed} static-reviewed, {len(data['drivers']) - reviewed} unchecked. NOT cancellation proof / NOT all-green.")
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print('Inventory check failed: ' + str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
