#!/usr/bin/env python3
"""Assemble an UNCHECKED snapshot plus explicitly supplied human-review shards.

This is a preparation helper, not an approval command. Inspect diffs/review all
source changes before replacing a checked-in inventory. Output must not exist.
"""
import argparse
import json
from pathlib import Path
import check_driver_inventory as inventory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo-root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('reviews', nargs='+', type=Path)
    args = parser.parse_args()
    data = inventory.draft(args.repo_root)
    reviewed = set()
    for path in args.reviews:
        for name, review in json.loads(path.read_text()).items():
            if name not in data['drivers'] or name in reviewed:
                raise ValueError('unknown/duplicate package: ' + name)
            reviewed.add(name)
            row = data['drivers'][name]
            row.update(review)
            row['cancel_proof'] = False
            row['support_status'] = 'unsupported-needs-review'
            for detail in row['operations'].values():
                detail['assessment'] = 'reviewed-static-not-cancel-proof'
                detail.setdefault('transport_ownership', row['transport_ownership'])
                detail.setdefault('unsupported_reason', 'Static boundary observations only; pinned dependencies, complete request chains, active-body cancellation and joined shutdown require separate implementation/test review. ' + detail['reason'])
    errors = inventory.check(args.repo_root, data)
    if errors:
        raise ValueError('\n'.join(errors))
    with args.output.open('x') as output:
        json.dump(data, output, indent=2, ensure_ascii=False)
        output.write('\n')
    print(f'Assembled {len(reviewed)} static reviews; no support promotion. Inspect output before delivery.')


if __name__ == '__main__':
    main()
