"""Regression tests for the follow-ups to the #32 review (issues #33, #34, #35).

#34 ``run_id`` was ``os.path.basename(run_dir.rstrip("/"))``: a trailing
    backslash (``--run "...\\run\\"`` on Windows) left an empty id, so the same run
    was REJECTed (``NEG.REPORT.SCHEMA_INVALID``) or ACCEPTed depending on how the
    path was spelled. The id now follows the host path semantics
    (``normpath``); ``ntpath``/``posixpath`` are pinned explicitly so the tests
    bite on every host, plus one end-to-end probe per host separator.
"""
from __future__ import annotations

import importlib
import json
import ntpath
import os
import posixpath
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "TOOLS"))

vr = importlib.import_module("validate_run")

GOOD = {"content_hash": "sha256:x", "version": "1.0.0", "payload": {}}
NAMES = ("model", "plan", "events", "schema", "env")


def _write_good_run(run_dir: Path) -> Path:
    kdir = run_dir / "kernels"
    kdir.mkdir(parents=True)
    for n in NAMES:
        (kdir / f"kernel.{n}.json").write_text(json.dumps(GOOD), encoding="utf-8")
    return run_dir


def _validate(run_dir) -> dict:
    """The contract is "a report, never an exception": a raise is a test verdict."""
    try:
        return vr.validate_run(run_dir)
    except Exception as exc:  # noqa: BLE001 - the type is part of the verdict
        raise AssertionError(
            f"validate_run crashed without a report: {type(exc).__name__}: {exc}"[:300]
        ) from exc


# ------------------------------- #34 run_id -------------------------------- #
@pytest.mark.parametrize(
    "raw",
    ["C:\\x\\run", "C:\\x\\run\\", "C:\\x\\run/", "C:/x/run/", "C:\\x\\run\\\\", "run\\"],
)
def test_run_id_windows_semantics_ignores_trailing_separators(raw):
    assert vr._run_id(raw, _path=ntpath) == "run"


@pytest.mark.parametrize("raw", ["/x/run", "/x/run/", "/x/run//", "run/"])
def test_run_id_posix_semantics_ignores_trailing_slashes(raw):
    assert vr._run_id(raw, _path=posixpath) == "run"


def test_run_id_posix_keeps_backslash_as_name_character():
    # On POSIX a backslash is part of the directory name, not a separator; the id
    # must name the directory that is actually opened.
    assert vr._run_id("/x/run\\", _path=posixpath) == "run\\"


@pytest.mark.parametrize("pathmod", [ntpath, posixpath])
def test_run_id_empty_stays_empty_so_the_report_rejects(pathmod):
    assert vr._run_id("", _path=pathmod) == ""


def test_run_id_accepts_pathlike(tmp_path):
    assert vr._run_id(tmp_path / "run") == "run"


@pytest.mark.parametrize("sep", sorted({os.sep, os.altsep or os.sep}))
def test_trailing_host_separator_gives_same_verdict_and_id(tmp_path, sep):
    run = _write_good_run(tmp_path / "run")
    plain = _validate(str(run))
    trailing = _validate(str(run) + sep)
    assert plain["status"] == "ACCEPT", plain
    assert trailing["run_id"] == plain["run_id"] == "run"
    assert trailing["status"] == plain["status"]
    assert trailing["hard_fail"] == plain["hard_fail"] == []


def test_empty_run_dir_is_still_rejected(tmp_path, monkeypatch):
    # "" would otherwise validate the cwd as run "."; keep it fail-closed.
    _write_good_run(tmp_path)
    monkeypatch.chdir(tmp_path)
    report = _validate("")
    assert report["status"] == "REJECT"
    assert "NEG.REPORT.SCHEMA_INVALID" in report["hard_fail"]
