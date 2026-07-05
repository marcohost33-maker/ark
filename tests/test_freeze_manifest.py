from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "TOOLS"
sys.path.insert(0, str(TOOLS))


@pytest.fixture(scope="module")
def freeze_mod():
    return importlib.import_module("freeze_manifest")


def test_freeze_manifest_in_sync_against_repo(freeze_mod):
    """Sync case -> green: the committed manifest matches the working tree."""
    negs = freeze_mod.verify_manifest(str(ROOT / "artifacts" / "FREEZE_MANIFEST_v1.0.5.json"))
    assert negs == [], negs


def _mini_repo(freeze_mod, tmp_path: Path) -> Path:
    """Build a tiny repo with one tracked file + a freeze manifest covering it."""
    repo = tmp_path / "repo"
    (repo / "artifacts").mkdir(parents=True)
    tracked = repo / "data.txt"
    tracked.write_text("hello\n", encoding="utf-8")
    manifest = {
        "artifact": "mini",
        "files": [
            {
                "path": "data.txt",
                "sha256": freeze_mod.sha256_file(str(tracked)),
                "bytes": tracked.stat().st_size,
            }
        ],
    }
    mpath = repo / "artifacts" / "manifest.json"
    mpath.write_text(json.dumps(manifest), encoding="utf-8")
    return repo


def _policy_repo_with_unpinned_required_file(freeze_mod, tmp_path: Path) -> Path:
    """Build a tiny repo where one required coverage file is not pinned."""
    repo = tmp_path / "policy-repo"
    (repo / "artifacts").mkdir(parents=True)
    (repo / "TOOLS").mkdir()
    pinned = repo / "TOOLS" / "known.py"
    unpinned = repo / "TOOLS" / "unpinned.py"
    pinned.write_text("VALUE = 1\n", encoding="utf-8")
    unpinned.write_text("VALUE = 2\n", encoding="utf-8")
    manifest = {
        "artifact": "mini-policy",
        "files": [
            {
                "path": "TOOLS/known.py",
                "sha256": freeze_mod.sha256_file(str(pinned)),
                "bytes": pinned.stat().st_size,
            }
        ],
    }
    (repo / "artifacts" / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return repo


def test_freeze_gate_green_when_synced(freeze_mod, tmp_path):
    repo = _mini_repo(freeze_mod, tmp_path)
    negs = freeze_mod.verify_manifest(str(repo / "artifacts" / "manifest.json"), root=str(repo))
    assert negs == []


def test_freeze_gate_red_on_content_drift(freeze_mod, tmp_path):
    """Drift case -> RED: file content changed after freeze -> MANIFEST_MISMATCH."""
    repo = _mini_repo(freeze_mod, tmp_path)
    (repo / "data.txt").write_text("hello world, grown\n", encoding="utf-8")
    negs = freeze_mod.verify_manifest(str(repo / "artifacts" / "manifest.json"), root=str(repo))
    assert "NEG.ARCHIVE.MANIFEST_MISMATCH" in negs


def test_freeze_gate_red_on_missing_file(freeze_mod, tmp_path):
    """Drift case -> RED: tracked file deleted -> MISSING_FILE."""
    repo = _mini_repo(freeze_mod, tmp_path)
    (repo / "data.txt").unlink()
    negs = freeze_mod.verify_manifest(str(repo / "artifacts" / "manifest.json"), root=str(repo))
    assert "NEG.ARCHIVE.MISSING_FILE" in negs


def test_freeze_gate_red_on_byte_only_drift(freeze_mod, tmp_path):
    """Even a same-hash-impossible byte mismatch must trip (defense in depth)."""
    repo = _mini_repo(freeze_mod, tmp_path)
    mpath = repo / "artifacts" / "manifest.json"
    manifest = json.loads(mpath.read_text(encoding="utf-8"))
    manifest["files"][0]["bytes"] = 9999  # tamper recorded length only
    mpath.write_text(json.dumps(manifest), encoding="utf-8")
    negs = freeze_mod.verify_manifest(str(mpath), root=str(repo))
    assert "NEG.ARCHIVE.MANIFEST_MISMATCH" in negs


def test_freeze_gate_red_on_unpinned_required_coverage_file(freeze_mod, tmp_path):
    """Coverage case -> RED: a required file class exists but is not pinned."""
    repo = _policy_repo_with_unpinned_required_file(freeze_mod, tmp_path)
    negs = freeze_mod.verify_manifest(str(repo / "artifacts" / "manifest.json"), root=str(repo))
    assert "NEG.ARCHIVE.UNPINNED_REQUIRED_FILE" in negs


def test_freeze_gate_red_on_duplicate_manifest_path(freeze_mod, tmp_path):
    """Duplicate path entries are ambiguous and must fail closed."""
    repo = _mini_repo(freeze_mod, tmp_path)
    mpath = repo / "artifacts" / "manifest.json"
    manifest = json.loads(mpath.read_text(encoding="utf-8"))
    manifest["files"].append(dict(manifest["files"][0]))
    mpath.write_text(json.dumps(manifest), encoding="utf-8")
    negs = freeze_mod.verify_manifest(str(mpath), root=str(repo))
    assert "NEG.ARCHIVE.MANIFEST_MISMATCH" in negs


def test_freeze_gate_red_on_empty_manifest(freeze_mod, tmp_path):
    repo = tmp_path / "r2"
    (repo / "artifacts").mkdir(parents=True)
    mpath = repo / "artifacts" / "manifest.json"
    mpath.write_text(json.dumps({"artifact": "x", "files": []}), encoding="utf-8")
    negs = freeze_mod.verify_manifest(str(mpath), root=str(repo))
    assert "NEG.ARCHIVE.MANIFEST_MISMATCH" in negs


def test_freeze_gate_red_on_malformed_manifest(freeze_mod, tmp_path):
    repo = tmp_path / "r3"
    (repo / "artifacts").mkdir(parents=True)
    mpath = repo / "artifacts" / "manifest.json"
    mpath.write_text("{ not json", encoding="utf-8")
    negs = freeze_mod.verify_manifest(str(mpath), root=str(repo))
    assert "NEG.ARCHIVE.MANIFEST_MISMATCH" in negs


def test_freeze_gate_red_if_manifest_pins_itself(freeze_mod, tmp_path):
    """The manifest must never pin its own path (chicken/egg) -> drift signal."""
    repo = tmp_path / "r4"
    (repo / "artifacts").mkdir(parents=True)
    real = repo / "artifacts" / "FREEZE_MANIFEST_v1.0.5.json"
    manifest = {
        "artifact": "x",
        "files": [{"path": "artifacts/FREEZE_MANIFEST_v1.0.5.json", "sha256": "0", "bytes": 0}],
    }
    real.write_text(json.dumps(manifest), encoding="utf-8")
    negs = freeze_mod.verify_manifest(str(real), root=str(repo))
    assert "NEG.ARCHIVE.MANIFEST_MISMATCH" in negs


def test_regenerate_then_verify_roundtrip(freeze_mod, tmp_path):
    """Regenerate from drifted tree -> verify green (re-freeze closes drift)."""
    repo = _mini_repo(freeze_mod, tmp_path)
    (repo / "data.txt").write_text("grown content here\n", encoding="utf-8")
    mpath = repo / "artifacts" / "manifest.json"
    new_manifest = freeze_mod.regenerate_manifest(str(mpath), root=str(repo))
    mpath.write_text(json.dumps(new_manifest), encoding="utf-8")
    negs = freeze_mod.verify_manifest(str(mpath), root=str(repo))
    assert negs == []


def test_regenerate_adds_missing_required_policy_paths(freeze_mod, tmp_path):
    """Regenerate must close required coverage gaps, not only refresh existing entries."""
    repo = _policy_repo_with_unpinned_required_file(freeze_mod, tmp_path)
    mpath = repo / "artifacts" / "manifest.json"
    new_manifest = freeze_mod.regenerate_manifest(str(mpath), root=str(repo))
    pinned = {e["path"] for e in new_manifest["files"]}
    assert {"TOOLS/known.py", "TOOLS/unpinned.py"} <= pinned
    mpath.write_text(json.dumps(new_manifest), encoding="utf-8")
    assert freeze_mod.verify_manifest(str(mpath), root=str(repo)) == []


def test_add_paths_extends_coverage_then_verify_green(freeze_mod, tmp_path):
    """add_paths pins a previously-untracked file; the gate is green afterward."""
    repo = _mini_repo(freeze_mod, tmp_path)
    extra = repo / "extra.txt"
    extra.write_text("more content\n", encoding="utf-8")
    mpath = repo / "artifacts" / "manifest.json"
    new_manifest = freeze_mod.add_paths(str(mpath), ["extra.txt"], root=str(repo))
    mpath.write_text(json.dumps(new_manifest), encoding="utf-8")
    pinned = {e["path"] for e in new_manifest["files"]}
    assert {"data.txt", "extra.txt"} <= pinned
    assert freeze_mod.verify_manifest(str(mpath), root=str(repo)) == []


def test_add_paths_rejects_nonexistent_file(freeze_mod, tmp_path):
    """Fail-closed: adding a path with no working-tree file raises (no silent skip)."""
    repo = _mini_repo(freeze_mod, tmp_path)
    mpath = repo / "artifacts" / "manifest.json"
    with pytest.raises(FileNotFoundError):
        freeze_mod.add_paths(str(mpath), ["ghost.txt"], root=str(repo))


def test_add_paths_refuses_to_pin_the_manifest_itself(freeze_mod, tmp_path):
    """Fail-closed: the manifest must never pin its own path (chicken/egg)."""
    repo = _mini_repo(freeze_mod, tmp_path)
    mpath = repo / "artifacts" / "manifest.json"
    with pytest.raises(ValueError):
        freeze_mod.add_paths(str(mpath), [freeze_mod.DEFAULT_MANIFEST], root=str(repo))


def test_add_paths_is_idempotent(freeze_mod, tmp_path):
    """Re-adding an already-covered path does not duplicate entries."""
    repo = _mini_repo(freeze_mod, tmp_path)
    mpath = repo / "artifacts" / "manifest.json"
    new_manifest = freeze_mod.add_paths(str(mpath), ["data.txt"], root=str(repo))
    paths = [e["path"] for e in new_manifest["files"]]
    assert paths.count("data.txt") == 1


def test_committed_manifest_pins_the_integrity_tool_itself(freeze_mod):
    """Issue #9 regression: the freeze tool + its tests are pinned by their own gate."""
    manifest = freeze_mod.load_manifest(
        str(ROOT / "artifacts" / "FREEZE_MANIFEST_v1.0.5.json")
    )
    pinned = {e["path"] for e in manifest["files"]}
    for required in (
        "TOOLS/freeze_manifest.py",
        "tests/test_freeze_manifest.py",
        "tests/test_semver.py",
        "tests/test_tools_smoke.py",
    ):
        assert required in pinned, f"self-trust gap: {required} not pinned"


def test_committed_manifest_covers_every_required_policy_path(freeze_mod):
    """ARK-NG-002 coverage-policy regression: no required class may be silently unpinned."""
    manifest = freeze_mod.load_manifest(
        str(ROOT / "artifacts" / "FREEZE_MANIFEST_v1.0.5.json")
    )
    pinned = {e["path"] for e in manifest["files"]}
    required = freeze_mod.discover_required_paths(str(ROOT))
    assert required <= pinned, f"unpinned required files: {sorted(required - pinned)}"
