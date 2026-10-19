"""Opt-in exit-code semantics for the validate_run CLI (issue #37).

Default stays as before (0 whenever a report was written, 1 on a policy error or
an unwritable report), so existing callers that read only the report keep
working. ``--strict-exit`` makes the exit code carry the verdict:
0 ACCEPT/ACCEPT_WITH_NOTES, 1 REJECT, 2 tool error, 3 REVIEW. 2 is argparse's own
usage-error code, so "the tool did not run cleanly" never looks like a verdict.
"""
from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "TOOLS"))

vr = importlib.import_module("validate_run")

GOOD = {"content_hash": "sha256:x", "version": "1.0.0", "payload": {}}
NAMES = ("model", "plan", "events", "schema", "env")


def _write_run(run_dir: Path, skip=()) -> Path:
    kdir = run_dir / "kernels"
    kdir.mkdir(parents=True)
    for n in NAMES:
        if n not in skip:
            (kdir / f"kernel.{n}.json").write_text(json.dumps(GOOD), encoding="utf-8")
    return run_dir


def _main(argv) -> int:
    try:
        return vr.main(argv)
    except BaseException as exc:  # noqa: BLE001 - SystemExit/tracebacks are verdicts too
        raise AssertionError(f"CLI raised instead of reporting: {type(exc).__name__}: {exc}"[:300]) from exc


def _status(path: Path) -> str:
    return json.loads(path.read_text(encoding="utf-8"))["status"]


# ------------------------------ pure mapping ------------------------------- #
@pytest.mark.parametrize(
    "status, code",
    [("ACCEPT", 0), ("ACCEPT_WITH_NOTES", 0), ("REJECT", 1), ("REVIEW", 3)],
)
def test_strict_exit_code_by_status(status, code):
    assert vr.strict_exit_code(status) == code


def test_strict_exit_covers_every_schema_status():
    enum = vr.report_schema_validator().schema["properties"]["status"]["enum"]
    assert set(enum) == set(vr._STRICT_EXIT_BY_STATUS)


@pytest.mark.parametrize("status", ["", "accept", "PASS", None, ["REVIEW"], {"s": 1}])
def test_strict_exit_unknown_status_fails_closed(status):
    assert vr.strict_exit_code(status) == vr.EXIT_REJECT


def _exit_vectors():
    paths = sorted((ROOT / "TESTVECTORS" / "exit").glob("*.json"))
    assert paths, "no testvectors under TESTVECTORS/exit"
    return [pytest.param(json.loads(p.read_text(encoding="utf-8")), id=p.stem) for p in paths]


@pytest.mark.parametrize("vec", _exit_vectors())
def test_strict_exit_golden_vectors(vec):
    # SPECS/REPORTING_POLICY_v1.md is the contract; the vectors are its oracle.
    assert vec["inputs"]["status"] == vec["expected"]["status"]
    assert vr.strict_exit_code(vec["inputs"]["status"]) == vec["expected"]["outputs"]["strict_exit"]


def test_golden_vectors_cover_every_schema_status():
    covered = {v.values[0]["expected"]["status"] for v in _exit_vectors()}
    assert covered == set(vr._STRICT_EXIT_BY_STATUS)


def test_tool_error_code_is_distinct_from_every_verdict():
    assert vr.EXIT_TOOL_ERROR not in set(vr._STRICT_EXIT_BY_STATUS.values())


# ------------------------------ CLI, default ------------------------------- #
def test_default_reject_still_exits_zero(tmp_path):
    run = _write_run(tmp_path / "run", skip=("plan",))
    out = tmp_path / "r.json"
    assert _main(["--run", str(run), "--out", str(out)]) == 0
    assert _status(out) == "REJECT"


# ------------------------------ CLI, strict -------------------------------- #
def test_strict_accept_exits_zero(tmp_path):
    run = _write_run(tmp_path / "run")
    out = tmp_path / "r.json"
    assert _main(["--run", str(run), "--out", str(out), "--strict-exit"]) == 0
    assert _status(out) == "ACCEPT"


def test_strict_reject_exits_one(tmp_path):
    run = _write_run(tmp_path / "run", skip=("plan",))
    out = tmp_path / "r.json"
    assert _main(["--run", str(run), "--out", str(out), "--strict-exit"]) == 1
    assert _status(out) == "REJECT"


def test_strict_review_exits_three(tmp_path, monkeypatch):
    # No finding validate_run routes today is downgradable to SOFT_FAIL, so a
    # REVIEW verdict is injected; the CLI mapping is what is under test.
    run = _write_run(tmp_path / "run")
    real = vr.validate_run

    def review(run_dir, policy=None):
        report = real(run_dir, policy=policy)
        report["status"] = "REVIEW"
        return report

    monkeypatch.setattr(vr, "validate_run", review)
    out = tmp_path / "r.json"
    assert _main(["--run", str(run), "--out", str(out), "--strict-exit"]) == 3
    assert _status(out) == "REVIEW"


def test_strict_policy_error_is_tool_error_with_reject_report(tmp_path):
    run = _write_run(tmp_path / "run")
    (run / "policy.json").write_text("{not json", encoding="utf-8")
    out = tmp_path / "r.json"
    assert _main(["--run", str(run), "--out", str(out), "--strict-exit"]) == 2
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["status"] == "REJECT"
    assert report["hard_fail"] == [vr.POLICY_UNREADABLE]


def test_strict_unwritable_report_is_tool_error(tmp_path):
    run = _write_run(tmp_path / "run")
    blocker = tmp_path / "blocker"
    blocker.write_text("x", encoding="utf-8")
    out = blocker / "sub" / "r.json"
    assert _main(["--run", str(run), "--out", str(out), "--strict-exit"]) == 2


def test_usage_error_shares_the_tool_error_code(capsys):
    with pytest.raises(SystemExit) as exc:
        vr.main(["--strict-exit"])  # --run missing
    assert exc.value.code == vr.EXIT_TOOL_ERROR
    capsys.readouterr()
