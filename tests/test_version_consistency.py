"""Version single source of truth (SPECS/VERSIONING_POLICY_v1.md).

``VERSION`` is the only place the ARK release version is set. Every lockstep copy
must match it on every PR, so a bump that misses one fails here and names it, and
the release workflow can verify ``tag == v<VERSION>``. The bump procedure of the
spec (section 5) is exercised end to end on a copy of the repository.
"""
from __future__ import annotations

import importlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "TOOLS"))

release_gate = importlib.import_module("release_gate")


def _read(root: Path, rel: str) -> str:
    return (root / rel).read_text(encoding="utf-8")


def read_version(root: Path) -> str:
    # One rule for PRs and releases: the release workflow runs TOOLS/release_gate.py,
    # which reads VERSION with exactly this function (raises a ValueError subclass).
    return release_gate.read_version(root)


def version_drift(root: Path) -> list[str]:
    """Every lockstep copy that disagrees with VERSION (empty = consistent)."""
    v = read_version(root)
    drift = []

    for spec in sorted((root / "SPECS").glob("*.md")):
        m = re.search(r"^Version: (\S+)$", spec.read_text(encoding="utf-8"), re.M)
        if not m or m.group(1) != v:
            drift.append(f"SPECS/{spec.name}: Version header {m.group(1) if m else None!r}")

    fm = re.search(
        r'^DEFAULT_MANIFEST = os\.path\.join\("artifacts", "([^"]+)"\)$',
        _read(root, "TOOLS/freeze_manifest.py"),
        re.M,
    )
    manifest_name = f"FREEZE_MANIFEST_v{v}.json"
    if not fm or fm.group(1) != manifest_name:
        drift.append(f"TOOLS/freeze_manifest.py: DEFAULT_MANIFEST {fm.group(1) if fm else None!r}")
    manifest = root / "artifacts" / manifest_name
    if not manifest.is_file():
        drift.append(f"artifacts/{manifest_name}: missing")
    elif json.loads(manifest.read_text(encoding="utf-8")).get("artifact") != f"ARK-Core_v{v}_freeze":
        drift.append(f"artifacts/{manifest_name}: artifact field")

    cff = re.search(r'^version: "?([^"\s]+)"?$', _read(root, "CITATION.cff"), re.M)
    if not cff or cff.group(1) != v:
        drift.append("CITATION.cff: version")

    if not re.search(rf"^- \*\*Version:\*\* {re.escape(v)} ", _read(root, "AGENTS.md"), re.M):
        drift.append("AGENTS.md: Version line")
    if not re.search(rf"^\*\*Status:\*\* v{re.escape(v)} ", _read(root, "README.md"), re.M):
        drift.append("README.md: Status line")

    prov = json.loads(_read(root, "examples/minimal_run/provenance/prov.json"))
    claimed = [a.get("tool_version") for a in prov.get("activities", []) if "tool_version" in a]
    claimed += [a.get("version") for a in prov.get("agents", []) if a.get("kind") == "tool"]
    if not claimed or any(c != v for c in claimed):
        drift.append(f"examples/minimal_run/provenance/prov.json: tool versions {claimed}")
    return drift


def test_version_file_is_strict_semver():
    assert read_version(ROOT)


@pytest.mark.parametrize("raw", ["1.0.5", "v1.0.5\n", "1.0.5 \n", "1.0.5\n\n", "1.0\n", "01.0.5\n"])
def test_malformed_version_file_is_rejected(tmp_path, raw):
    (tmp_path / "VERSION").write_text(raw, encoding="utf-8")
    with pytest.raises(ValueError):
        read_version(tmp_path)


def test_all_lockstep_copies_match_version():
    assert version_drift(ROOT) == []


def test_release_workflow_derives_version_and_gates_the_tag():
    wf = _read(ROOT, ".github/workflows/release.yml")
    # No hard-coded manifest version: the release must follow VERSION.
    assert not re.search(r"FREEZE_MANIFEST_v\d", wf), "release.yml hard-codes a manifest version"
    # The gate is the Python tool (strict SemVer, tag-only), not a shell character class.
    assert "run: python TOOLS/release_gate.py\n" in wf
    assert "case " not in wf, "shell case pattern is back in release.yml"
    # Template injection in run scripts is audited by zizmor (required CI check).


# ----------------------- bump procedure, end to end ------------------------ #
def _run(*args: str) -> int:
    return subprocess.run([sys.executable, *args], capture_output=True, text=True, timeout=120).returncode


def _sub(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    assert old in text, f"{path}: {old!r} not found"
    path.write_text(text.replace(old, new), encoding="utf-8")


def test_bump_procedure_end_to_end(tmp_path):
    repo = tmp_path / "repo"
    shutil.copytree(
        ROOT, repo, ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache", ".ruff_cache")
    )
    old = read_version(repo)
    new = "1.1.0" if old != "1.1.0" else "1.2.0"

    # Step 1: only VERSION changed -> the gate names the stale copies.
    # LF as enforced by .gitattributes; the release gate refuses a CRLF VERSION.
    (repo / "VERSION").write_text(new + "\n", encoding="utf-8", newline="\n")
    stale = version_drift(repo)
    assert any(s.startswith("SPECS/") for s in stale)
    assert any("DEFAULT_MANIFEST" in s for s in stale)

    # Step 2: lockstep copies.
    for spec in (repo / "SPECS").glob("*.md"):
        _sub(spec, f"Version: {old}\n", f"Version: {new}\n")
    _sub(repo / "CITATION.cff", f'version: "{old}"', f'version: "{new}"')
    _sub(repo / "AGENTS.md", f"**Version:** {old} ", f"**Version:** {new} ")
    _sub(repo / "README.md", f"**Status:** v{old} ", f"**Status:** v{new} ")
    _sub(repo / "examples/minimal_run/provenance/prov.json", f'"{old}"', f'"{new}"')

    # Step 3: new manifest from the previous one, then re-freeze.
    old_m = repo / "artifacts" / f"FREEZE_MANIFEST_v{old}.json"
    new_m = repo / "artifacts" / f"FREEZE_MANIFEST_v{new}.json"
    data = json.loads(old_m.read_text(encoding="utf-8"))
    data["artifact"] = f"ARK-Core_v{new}_freeze"
    new_m.write_text(json.dumps(data, indent=2), encoding="utf-8")
    _sub(repo / "TOOLS/freeze_manifest.py", f"FREEZE_MANIFEST_v{old}.json", f"FREEZE_MANIFEST_v{new}.json")
    assert _run(str(repo / "TOOLS/freeze_manifest.py"), "--regenerate") == 0

    assert version_drift(repo) == []
    assert _run(str(repo / "TOOLS/freeze_manifest.py")) == 0  # NG-002 gate in sync
