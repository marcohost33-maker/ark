#!/usr/bin/env python3
"""Freeze-manifest generation + verification (enforces ARK-NG-002: no silent manifest drift).

Deterministic, stdlib-only. The manifest is the integrity truth for the freeze line:
each listed file is pinned by SHA-256 + byte length. ``verify_manifest`` is fail-closed —
any mismatch / missing / extra tracked file yields a non-empty NEG list, which the CI gate
(and ``__main__`` exit code) treats as a hard failure.

The manifest file cannot hash itself (writing the digest changes the digest), so the
manifest's own path is excluded from the ``files`` list by construction; the verifier
treats that exclusion as expected, not as drift.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Dict, List

# Default freeze manifest, relative to the repository root.
DEFAULT_MANIFEST = os.path.join("artifacts", "FREEZE_MANIFEST_v1.0.5.json")

# Paths (relative, POSIX-style) excluded from the manifest's own file list.
# The manifest cannot contain its own hash (chicken/egg); excluding it is correct,
# not drift.
SELF_EXCLUDE = {DEFAULT_MANIFEST.replace(os.sep, "/")}


def _repo_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def compute_entries(root: str, paths: List[str]) -> List[Dict[str, object]]:
    """Compute {path, sha256, bytes} for each given repo-relative path, sorted by path."""
    entries: List[Dict[str, object]] = []
    for rel in sorted(paths):
        if rel in SELF_EXCLUDE:
            continue
        abs_path = os.path.join(root, rel.replace("/", os.sep))
        entries.append(
            {
                "path": rel,
                "sha256": sha256_file(abs_path),
                "bytes": os.path.getsize(abs_path),
            }
        )
    return entries


def load_manifest(manifest_path: str) -> Dict[str, object]:
    with open(manifest_path, "r", encoding="utf-8") as f:
        return json.load(f)


def verify_manifest(manifest_path: str, root: str | None = None) -> List[str]:
    """Verify every manifest entry against the working tree. Fail-closed.

    Returns a sorted, de-duplicated list of NEG IDs. Empty list == in sync.
    """
    root = root or _repo_root()
    neg: List[str] = []
    try:
        manifest = load_manifest(manifest_path)
    except (OSError, json.JSONDecodeError):
        return ["NEG.ARCHIVE.MANIFEST_MISMATCH"]

    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        return ["NEG.ARCHIVE.MANIFEST_MISMATCH"]

    for entry in files:
        rel = entry.get("path")
        if not isinstance(rel, str):
            neg.append("NEG.ARCHIVE.MANIFEST_MISMATCH")
            continue
        if rel in SELF_EXCLUDE:
            # The manifest must not pin itself.
            neg.append("NEG.ARCHIVE.MANIFEST_MISMATCH")
            continue
        abs_path = os.path.join(root, rel.replace("/", os.sep))
        if not os.path.exists(abs_path):
            neg.append("NEG.ARCHIVE.MISSING_FILE")
            continue
        actual_sha = sha256_file(abs_path)
        actual_bytes = os.path.getsize(abs_path)
        if actual_sha != entry.get("sha256") or actual_bytes != entry.get("bytes"):
            neg.append("NEG.ARCHIVE.MANIFEST_MISMATCH")
    return sorted(set(neg))


def regenerate_manifest(manifest_path: str, root: str | None = None) -> Dict[str, object]:
    """Re-freeze: rebuild the ``files`` list from the current working tree, preserving
    the manifest's existing paths (minus the self-reference) and other top-level keys."""
    root = root or _repo_root()
    manifest = load_manifest(manifest_path)
    paths = [
        e["path"]
        for e in manifest.get("files", [])
        if isinstance(e, dict) and isinstance(e.get("path"), str)
    ]
    manifest["files"] = compute_entries(root, paths)
    manifest["created_utc"] = datetime.now(timezone.utc).isoformat()
    return manifest


if __name__ == "__main__":
    import argparse
    import sys

    ap = argparse.ArgumentParser(description="Freeze-manifest verify/regenerate (ARK-NG-002).")
    ap.add_argument("--manifest", default=os.path.join(_repo_root(), DEFAULT_MANIFEST))
    ap.add_argument(
        "--regenerate",
        action="store_true",
        help="Re-freeze the manifest against the current working tree.",
    )
    args = ap.parse_args()

    if args.regenerate:
        new_manifest = regenerate_manifest(args.manifest)
        with open(args.manifest, "w", encoding="utf-8") as f:
            json.dump(new_manifest, f, indent=2)
            f.write("\n")
        print(f"re-froze {args.manifest} ({len(new_manifest['files'])} files)")
        sys.exit(0)

    negs = verify_manifest(args.manifest)
    if negs:
        print("FREEZE MANIFEST DRIFT (NG-002 violated):", file=sys.stderr)
        for n in negs:
            print("  " + n, file=sys.stderr)
        sys.exit(1)
    print("freeze manifest in sync")
    sys.exit(0)
