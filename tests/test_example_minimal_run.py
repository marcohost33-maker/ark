"""Golden smoke test for the minimal end-to-end example (issue #17).

Runs the committed example pipeline into a temp dir and asserts the output
artifacts equal the golden `expected/` files on every field except the
wall-clock `created_utc`.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "minimal_run"


def _load_pipeline():
    spec = importlib.util.spec_from_file_location(
        "ark_example_pipeline", ROOT / "examples" / "run_pipeline.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _normalize(doc: dict) -> dict:
    out = dict(doc)
    out["created_utc"] = "__NORMALIZED__"
    return out


def test_example_pipeline_runs_and_matches_golden(tmp_path):
    pipeline = _load_pipeline()
    result = pipeline.run_pipeline(str(EXAMPLE))

    # Positive behavior: clean minimal run accepts with no negatives.
    assert result["gate_report"]["status"] == "ACCEPT"
    assert result["gate_report"]["hard_fail"] == []
    assert result["gate_report"]["soft_fail"] == []
    assert result["prov_neg_ids"] == []

    # Golden equality (created_utc normalized).
    assert _normalize(result["gate_report"]) == _read(EXAMPLE / "expected" / "gate_report.json")
    assert _normalize(result["evidence_profile"]) == _read(
        EXAMPLE / "expected" / "evidence_profile.json"
    )


def test_example_pipeline_main_writes_artifacts(tmp_path, monkeypatch):
    pipeline = _load_pipeline()
    out_dir = tmp_path / "reports"
    monkeypatch.setattr(
        "sys.argv",
        ["run_pipeline.py", "--run", str(EXAMPLE), "--out-dir", str(out_dir)],
    )
    assert pipeline.main() == 0
    written = _read(out_dir / "gate_report.json")
    assert written["status"] == "ACCEPT"
    assert (out_dir / "evidence_profile.json").exists()


def test_example_replay_is_deterministic_modulo_timestamp(tmp_path):
    """Deterministic replay: two runs are identical except for created_utc."""
    pipeline = _load_pipeline()
    first = _normalize(pipeline.run_pipeline(str(EXAMPLE))["gate_report"])
    second = _normalize(pipeline.run_pipeline(str(EXAMPLE))["gate_report"])
    assert first == second


def test_example_negative_missing_kernel_is_rejected(tmp_path):
    """Negative behavior: removing a kernel file flips the example to REJECT."""
    import shutil

    broken = tmp_path / "broken_run"
    shutil.copytree(EXAMPLE, broken)
    (broken / "kernels" / "kernel.model.json").unlink()
    pipeline = _load_pipeline()
    report = pipeline.run_pipeline(str(broken))["gate_report"]
    assert report["status"] == "REJECT"
    assert "NEG.KERNEL.MISSING_MODEL" in report["hard_fail"]


def test_example_expected_files_are_valid_status(tmp_path):
    """Guard: committed golden files stay parseable + ACCEPT (no silent rot)."""
    for name in ("gate_report.json", "evidence_profile.json"):
        doc = _read(EXAMPLE / "expected" / name)
        assert doc["status"] == "ACCEPT"
        assert doc["created_utc"] == "__NORMALIZED__"


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
