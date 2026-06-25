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
