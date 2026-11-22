#!/usr/bin/env python3
"""Freeze-manifest generation + verification (enforces ARK-NG-002: no silent manifest drift).

Deterministic, stdlib-only. The manifest is the integrity truth for the freeze line:
each listed file is pinned by SHA-256 + byte length. ``verify_manifest`` is fail-closed —
any mismatch / missing required file / unpinned required coverage file yields a non-empty
NEG list, which the CI gate (and ``__main__`` exit code) treats as a hard failure.

The manifest file cannot hash itself (writing the digest changes the digest), so the
manifest's own path is excluded from the ``files`` list by construction; the verifier
treats that exclusion as expected, not as drift.

Coverage is extended with ``--add PATH ...`` (tool-native, fail-closed) rather than by
hand-editing the JSON: this is how the integrity tool, its tests, and other
integrity-relevant files get pinned by their own gate (closing the self-trust gap of
ARK-NG-002). See ``docs/FREEZE_COVERAGE_POLICY.md`` for which file classes MUST be pinned.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from fnmatch import fnmatch
from typing import Dict, List, Set

# ``python -I`` implies ``-P`` (3.11+): the script's directory is not on sys.path.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ark_json  # noqa: E402  (the one JSON grammar, I-JSON, stdlib only)

# Default freeze manifest, relative to the repository root.
DEFAULT_MANIFEST = os.path.join("artifacts", "FREEZE_MANIFEST_v1.1.0.json")

# Paths (relative, POSIX-style) excluded from the manifest's own file list.
# The manifest cannot contain its own hash (chicken/egg); excluding it is correct,
# not drift.
SELF_EXCLUDE = {DEFAULT_MANIFEST.replace(os.sep, "/")}

# Coverage policy: every existing file matching one of these rules MUST be pinned.
# Keep this in sync with docs/FREEZE_COVERAGE_POLICY.md.
REQUIRED_EXACT_PATHS = {
    ".gitattributes",
    "CHANGELOG.md",
    "LICENSE",
    "README.md",
    "VERSION",
    "docs/FREEZE_COVERAGE_POLICY.md",
    "docs/architecture_overview.md",
}
REQUIRED_GLOBS = {
    "TOOLS/*.py",
    "tests/*.py",
    "SCHEMAS/*.json",
    "SPECS/*.md",
    "TESTVECTORS/**",
    "artifacts/FREEZE_SUMMARY_*.md",
    "tocs/*",
}
IGNORED_DIRS = {".git", "__pycache__", ".pytest_cache", ".ruff_cache", ".mypy_cache"}


def _repo_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _rel_posix(root: str, path: str) -> str:
    return os.path.relpath(path, root).replace(os.sep, "/")


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _matches_required_glob(rel: str) -> bool:
    return any(fnmatch(rel, pattern) for pattern in REQUIRED_GLOBS)


def discover_required_paths(root: str) -> Set[str]:
    """Return repo-relative paths that the coverage policy requires to be pinned.

    This intentionally uses an explicit allowlist of integrity-relevant file classes,
    not "all files in the repo": roadmap/process/support files may change outside the
    frozen ARK evidence surface, while validators, specs, schemas, testvectors,
    freeze docs, and LF normalization are load-bearing and must trip NG-002 if unpinned.
    """
    required: Set[str] = set()
    for rel in REQUIRED_EXACT_PATHS:
        abs_path = os.path.join(root, rel.replace("/", os.sep))
        if os.path.isfile(abs_path):
            required.add(rel)

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
        for filename in filenames:
            abs_path = os.path.join(dirpath, filename)
            rel = _rel_posix(root, abs_path)
            if rel in SELF_EXCLUDE:
                continue
            if _matches_required_glob(rel):
                required.add(rel)
    return required


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


def strict_json_loads(text: str) -> object:
    """I-JSON parse (RFC 7493), see ``ark_json``. Kept as the public name used since #45."""
    return ark_json.loads(text)


def load_manifest(manifest_path: str) -> Dict[str, object]:
    with open(manifest_path, "r", encoding="utf-8") as f:
        return strict_json_loads(f.read())


def verify_manifest(manifest_path: str, root: str | None = None) -> List[str]:
    """Verify every manifest entry and every required coverage path. Fail-closed.

    Returns a sorted, de-duplicated list of NEG IDs. Empty list == in sync.
    """
    root = root or _repo_root()
    neg: List[str] = []
    try:
        manifest = load_manifest(manifest_path)
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
        # ValueError covers JSONDecodeError, duplicate keys and NaN/Infinity (strict_json_loads).
        return ["NEG.ARCHIVE.MANIFEST_MISMATCH"]
    if not isinstance(manifest, dict):
        return ["NEG.ARCHIVE.MANIFEST_MISMATCH"]

    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        return ["NEG.ARCHIVE.MANIFEST_MISMATCH"]

    pinned_paths: Set[str] = set()
    for entry in files:
        if not isinstance(entry, dict):
            neg.append("NEG.ARCHIVE.MANIFEST_MISMATCH")
            continue
        rel = entry.get("path")
        if not isinstance(rel, str):
            neg.append("NEG.ARCHIVE.MANIFEST_MISMATCH")
            continue
        if rel in pinned_paths:
            neg.append("NEG.ARCHIVE.MANIFEST_MISMATCH")
        pinned_paths.add(rel)
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

    missing_required = discover_required_paths(root) - pinned_paths
    if missing_required:
        neg.append("NEG.ARCHIVE.UNPINNED_REQUIRED_FILE")

    return sorted(set(neg))


def regenerate_manifest(manifest_path: str, root: str | None = None) -> Dict[str, object]:
    """Re-freeze from current manifest paths plus all required policy paths."""
    root = root or _repo_root()
    manifest = load_manifest(manifest_path)
    paths = {
        e["path"]
        for e in manifest.get("files", [])
        if isinstance(e, dict) and isinstance(e.get("path"), str)
    }
    paths.update(discover_required_paths(root))
    manifest["files"] = compute_entries(root, sorted(paths))
    manifest["created_utc"] = datetime.now(timezone.utc).isoformat()
    return manifest


def add_paths(
    manifest_path: str, new_paths: List[str], root: str | None = None
) -> Dict[str, object]:
    """Extend manifest coverage by ``new_paths``, then re-freeze every entry.

    Fail-closed: adding a non-existent file, or attempting to pin the manifest's own
    path, raises rather than silently writing a bad manifest. Idempotent: re-adding an
    already-covered path is a no-op (paths are de-duplicated and sorted).
    """
    root = root or _repo_root()
    manifest = load_manifest(manifest_path)
    covered = {
        e["path"]
        for e in manifest.get("files", [])
        if isinstance(e, dict) and isinstance(e.get("path"), str)
    }
    for raw in new_paths:
        rel = raw.replace(os.sep, "/")
        if rel in SELF_EXCLUDE:
            raise ValueError(f"refusing to pin the manifest's own path: {rel}")
        abs_path = os.path.join(root, rel.replace("/", os.sep))
        if not os.path.isfile(abs_path):
            raise FileNotFoundError(f"cannot add non-existent file: {rel}")
        covered.add(rel)
    covered.update(discover_required_paths(root))
    manifest["files"] = compute_entries(root, sorted(covered))
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
    ap.add_argument(
        "--add",
        nargs="+",
        metavar="PATH",
        help="Add repo-relative path(s) to manifest coverage, then re-freeze all entries.",
    )
    args = ap.parse_args()

    if args.add:
        new_manifest = add_paths(args.manifest, args.add)
        with open(args.manifest, "w", encoding="utf-8", newline="\n") as f:  # LF on every OS
            json.dump(new_manifest, f, indent=2)
            f.write("\n")
        print(f"added {len(args.add)} path(s); manifest now pins {len(new_manifest['files'])} files")
        sys.exit(0)

    if args.regenerate:
        new_manifest = regenerate_manifest(args.manifest)
        with open(args.manifest, "w", encoding="utf-8", newline="\n") as f:  # LF on every OS
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
