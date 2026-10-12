#!/usr/bin/env python3
"""Fail closed before applying the narrow, reviewed OpenList source overlay."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import sys

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
PREFIXES = ("internal/", "pkg/singleflight/", "pkg/utils/", "server/",
            "drivers/google_drive/", "drivers/onedrive/", "drivers/mega/")


class OverlayError(ValueError):
    pass


def load_manifest(path, file_list):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("version") != 1 or not re.fullmatch(r"[0-9a-f]{40}", data.get("upstream_commit", "")):
        raise OverlayError("invalid source overlay manifest version/commit")
    if not isinstance(data.get("upstream_tag"), str) or not data["upstream_tag"]:
        raise OverlayError("missing pinned upstream tag")
    files = data.get("files")
    if not isinstance(files, dict) or not files:
        raise OverlayError("missing source overlay files")
    names = Path(file_list).read_text(encoding="utf-8").splitlines()
    if len(set(names)) != len(names) or set(names) != set(files):
        raise OverlayError("overlay file list and fingerprint manifest disagree")
    for name, digest in files.items():
        parts = PurePosixPath(name)
        if (not name.startswith(PREFIXES) or parts.is_absolute() or ".." in parts.parts
                or str(parts) != name or "\\" in name):
            raise OverlayError("invalid overlay path: " + name)
        if digest is not None and (not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)):
            raise OverlayError("invalid pristine fingerprint: " + name)
    return data


def safe_file(root, name):
    root = Path(root).resolve()
    path = root / name
    cursor = path
    while cursor != root:
        if cursor.is_symlink():
            raise OverlayError("symlink not permitted in controlled overlay: " + name)
        cursor = cursor.parent
    return path


def digest_file(path):
    if not path.is_file():
        raise OverlayError("missing/non-regular overlay file: " + str(path))
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_pin(manifest, tag, commit=None):
    if tag != manifest["upstream_tag"]:
        raise OverlayError("upstream tag changed; review and regenerate pristine fingerprints before upgrading")
    if commit is not None and commit != manifest["upstream_commit"]:
        raise OverlayError("upstream tag commit differs from reviewed pristine commit")


def check_mirrors(manifest, root):
    """Never use an already-patched mirror as proof of pristine upstream provenance."""
    for name in manifest["files"]:
        actual = safe_file(root, name)
        mirror = safe_file(Path(root) / "src", name)
        if digest_file(actual) != digest_file(mirror):
            raise OverlayError("actual/src overlay drift; review both copies before init: " + name)


def verify_pristine(manifest, root, tag, commit):
    verify_pin(manifest, tag, commit)
    for name, expected in manifest["files"].items():
        path = safe_file(root, name)
        if expected is None:
            if path.exists():
                raise OverlayError("upstream collides with locally added overlay file: " + name)
        elif digest_file(path) != expected:
            raise OverlayError("pristine upstream content changed; three-way review required: " + name)


def apply_overlay(manifest, pristine_root, overlay_root, tag, commit):
    # Preflight EVERY source and target first. No earlier file is overwritten on
    # a later fingerprint/missing-file failure. This is not a filesystem transaction
    # against concurrent external writers; init uses a private staging checkout.
    verify_pristine(manifest, pristine_root, tag, commit)
    sources = []
    for name in manifest["files"]:
        source = safe_file(overlay_root, name)
        digest_file(source)
        sources.append((source, safe_file(pristine_root, name)))
    for source, target in sources:
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=SCRIPT_DIR / "source_overlay_manifest.json")
    parser.add_argument("--file-list", type=Path, default=SCRIPT_DIR / "playback_resilience_files.txt")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--tag")
    parser.add_argument("--commit")
    parser.add_argument("--upstream-root", type=Path)
    parser.add_argument("--overlay-root", type=Path)
    parser.add_argument("--check-mirrors", action="store_true")
    args = parser.parse_args()
    try:
        manifest = load_manifest(args.manifest, args.file_list)
        tag = args.tag if args.tag is not None else (args.root / "UPSTREAM_VERSION").read_text().strip()
        verify_pin(manifest, tag, args.commit)
        if args.check_mirrors:
            check_mirrors(manifest, args.root)
        elif args.upstream_root is not None:
            if args.commit is None:
                raise OverlayError("pristine verification requires the actual cloned commit")
            if args.overlay_root is None:
                verify_pristine(manifest, args.upstream_root, tag, args.commit)
            else:
                apply_overlay(manifest, args.upstream_root, args.overlay_root, tag, args.commit)
        else:
            raise OverlayError("choose --check-mirrors or --upstream-root")
    except (OverlayError, OSError, ValueError) as exc:
        print("Source overlay verification failed: " + str(exc), file=sys.stderr)
        return 1
    print("Source overlay verified: %d files, %s at %s" % (
        len(manifest["files"]), manifest["upstream_tag"], manifest["upstream_commit"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
