from __future__ import annotations

import importlib
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "TOOLS"
sys.path.insert(0, str(TOOLS))


def test_all_documented_tools_import() -> None:
    for module_name in (
        "validate_run",
        "provenance_validate",
        "event_hysteresis",
        "severity_mapping",
        "root_finding",
        "contradiction_rules",
    ):
        importlib.import_module(module_name)


def test_validate_run_rejects_missing_kernel_files(tmp_path: Path) -> None:
    validate_run = importlib.import_module("validate_run")
    run_dir = tmp_path / "empty-run"
    run_dir.mkdir()

    report = validate_run.validate_run(str(run_dir))

    assert report["status"] == "REJECT"
    assert any(item.startswith("NEG.KERNEL.MISSING_") for item in report["hard_fail"])
