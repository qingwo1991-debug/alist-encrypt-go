#!/usr/bin/env python3
"""Manually sync reviewed, listed actual build files to src (preview by default)."""
import argparse
import os
from pathlib import Path
import stat
import sys
import tempfile

import verify_source_overlay as overlay


def require_regular(path):
    """Reject special files and symlinks, including symlinked parent directories."""
    path = Path(path).absolute()
    for cursor in (path, *path.parents):
        if cursor.is_symlink():
            raise overlay.OverlayError("symlink not permitted in manual sync: " + str(cursor))
    if not stat.S_ISREG(path.stat().st_mode):
        raise overlay.OverlayError("missing/non-regular manual sync file: " + str(path))
    return path


def preflight(root, manifest_path, file_list):
    """Validate the complete batch before returning any proposed replacements."""
    root = Path(root)
    manifest_path = require_regular(manifest_path)
    file_list = require_regular(file_list)
    version = require_regular(root / "UPSTREAM_VERSION")
    manifest = overlay.load_manifest(manifest_path, file_list)
    overlay.verify_pin(manifest, version.read_text(encoding="utf-8").strip())
    changes = []
    for name in manifest["files"]:
        actual = require_regular(root / name)
        mirror = require_regular(root / "src" / name)
        content = actual.read_bytes()
        if content != mirror.read_bytes():
            changes.append((name, mirror, content, stat.S_IMODE(mirror.stat().st_mode)))
    return changes


def sync(root, manifest_path, file_list, apply=False):
    changes = preflight(root, manifest_path, file_list)
    if apply:
        for _, target, content, mode in changes:
            # Replace only this directory entry, never mutate a hardlinked peer.
            # Atomic per file, NOT a transaction across the batch or concurrent edits.
            temp_path = None
            try:
                with tempfile.NamedTemporaryFile(dir=target.parent, prefix=".overlay-sync-",
                                                 delete=False) as temp:
                    temp_path = Path(temp.name)
                    temp.write(content)
                temp_path.chmod(mode)
                os.replace(temp_path, target)
            finally:
                if temp_path is not None:
                    temp_path.unlink(missing_ok=True)
    return [name for name, _, _, _ in changes]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=overlay.ROOT)
    parser.add_argument("--manifest", type=Path,
                        default=overlay.SCRIPT_DIR / "source_overlay_manifest.json")
    parser.add_argument("--file-list", type=Path,
                        default=overlay.SCRIPT_DIR / "playback_resilience_files.txt")
    parser.add_argument("--apply", action="store_true",
                        help="overwrite listed src mirrors from actual files after manual review")
    args = parser.parse_args(argv)
    try:
        names = sync(args.root, args.manifest, args.file_list, apply=args.apply)
    except (overlay.OverlayError, OSError, ValueError, TypeError, AttributeError) as exc:
        print("Source overlay sync failed: " + str(exc), file=sys.stderr)
        return 1
    for name in names:
        print(("Synced: " if args.apply else "Would sync: ") + name)
    print("%d listed mirror(s) %s; pristine fingerprints unchanged." % (
        len(names), "synced" if args.apply else "would change (review before --apply)"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
