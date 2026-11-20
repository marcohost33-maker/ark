#!/usr/bin/env python3
"""Release tag gate (SPECS/VERSIONING_POLICY_v1.md, section 1 and 5).

Run by ``.github/workflows/release.yml`` before anything is built or attested.
It replaces a shell ``case`` pattern that only checked the character set of
``VERSION``: ``invalid-version``, ``1.0.5.6`` or ``01.0.5`` passed it whenever
tag and manifest name matched (cross-family review ARK-P1-01, 2026-10-19), and a
manual dispatch on a branch passed it without any tag at all (ARK-P1-02).

Rules, all fail-closed (exit 1, nothing written to ``GITHUB_OUTPUT``):

* ``VERSION`` is exactly one strict SemVer 2.0.0 line ending in ``\\n``. The
  grammar is ``ark_semver.SEMVER_RE`` (the semver.org regex, ASCII digits only),
  matched in full; ``validate_run`` and ``tests/test_version_consistency.py`` use
  the same module.
* The workflow runs on a tag: ``GITHUB_REF_TYPE == "tag"``. A branch ref is not
  a release, so a manual dispatch on a branch attests nothing.
* ``GITHUB_REF_NAME == "v" + VERSION``.
* ``artifacts/FREEZE_MANIFEST_v<VERSION>.json`` exists, is a JSON object and its
  ``artifact`` field reads ``ARK-Core_v<VERSION>_freeze``.

On success it appends ``version=<VERSION>`` to ``GITHUB_OUTPUT`` and exits 0.
Only environment variables and repository files are read; no workflow
expression is expanded into a script (template-injection safe).
Standard library only: the gate runs before ``pip install`` in the release job,
so it must not import ``validate_run`` (which needs ``jsonschema``; ARK-EQ-02).
Exit 2 is a usage/environment error (e.g. ``GITHUB_OUTPUT`` unset).
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ark_json  # noqa: E402  (the one JSON grammar, I-JSON, stdlib only)
from ark_semver import SEMVER_RE  # noqa: E402  (single SemVer grammar, stdlib only)


class ReleaseGateError(ValueError):
    """The release must not proceed."""


def is_semver(text: str) -> bool:
    return isinstance(text, str) and SEMVER_RE.fullmatch(text) is not None


def read_version(root: Path) -> str:
    """Return the release version from ``VERSION`` or raise :class:`ReleaseGateError`."""
    try:
        raw_bytes = (root / "VERSION").read_bytes()
    except OSError as exc:
        raise ReleaseGateError(f"VERSION unreadable: {exc}") from exc
    try:
        raw = raw_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ReleaseGateError("VERSION is not UTF-8") from exc
    if not raw.endswith("\n") or raw.count("\n") != 1:
        raise ReleaseGateError(f"VERSION must be exactly one line ending in a newline, got {raw!a}")
    version = raw[:-1]
    if not is_semver(version):
        raise ReleaseGateError(f"VERSION is not strict SemVer 2.0.0: {version!a}")
    return version


def check_release(root: Path, ref_type: str | None, ref_name: str | None) -> str:
    """Return the version to release, or raise :class:`ReleaseGateError`."""
    version = read_version(root)
    if ref_type != "tag":
        raise ReleaseGateError(
            f"release runs only on a tag ref, got ref type {ref_type!a} ({ref_name!a}); "
            "a branch dispatch attests nothing"
        )
    if ref_name != f"v{version}":
        raise ReleaseGateError(f"tag {ref_name!a} does not match VERSION (expected 'v{version}')")
    manifest = root / "artifacts" / f"FREEZE_MANIFEST_v{version}.json"
    try:
        data = ark_json.loads(manifest.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ReleaseGateError(f"no freeze manifest for VERSION {version}") from exc
    except (OSError, ValueError) as exc:
        raise ReleaseGateError(f"freeze manifest for VERSION {version} unreadable: {exc}") from exc
    if not isinstance(data, dict) or data.get("artifact") != f"ARK-Core_v{version}_freeze":
        raise ReleaseGateError(f"freeze manifest artifact field does not name ARK-Core_v{version}_freeze")
    return version


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    args = parser.parse_args(argv)
    output = os.environ.get("GITHUB_OUTPUT")
    if not output:
        print("release gate: GITHUB_OUTPUT is not set", file=sys.stderr)
        return 2
    try:
        version = check_release(
            Path(args.root), os.environ.get("GITHUB_REF_TYPE"), os.environ.get("GITHUB_REF_NAME")
        )
    except ReleaseGateError as exc:
        # ASCII-safe: a console that cannot encode the message must not turn the
        # refusal into a crash with the same exit code.
        print(f"release gate: {exc}".encode("ascii", "backslashreplace").decode("ascii"), file=sys.stderr)
        return 1
    with open(output, "a", encoding="utf-8", newline="\n") as fh:
        fh.write(f"version={version}\n")
    print(f"release gate: v{version} ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
