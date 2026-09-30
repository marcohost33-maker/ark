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


def test_issue34_trailing_backslash_on_windows_is_not_an_empty_id():
    # The exact report of #34: --run "...\run\" on Windows.
    assert vr._run_id("C:\\runs\\run\\", _path=ntpath) == "run"


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


# ------------------------- #33 policy error -> REJECT ----------------------- #
# The API keeps raising PolicyError (docs/API.md); the CLI must turn it into a
# REJECT report with NEG.POLICY.UNREADABLE and exit non-zero. If that report cannot
# be written, an older report at the output path is removed where the filesystem
# allows it (docs/API.md); the exit code is 1 either way.
POLICY_UNREADABLE = "NEG.POLICY.UNREADABLE"


def _stale_accept(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"status": "ACCEPT", "run_id": "stale"}), encoding="utf-8")


def _main(argv) -> int:
    try:
        return vr.main(argv)
    except BaseException as exc:  # noqa: BLE001 - SystemExit/tracebacks are verdicts too
        raise AssertionError(f"CLI raised instead of reporting: {type(exc).__name__}: {exc}"[:300]) from exc


def _assert_policy_reject(report_path: Path) -> dict:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["status"] == "REJECT", report
    assert report["hard_fail"] == [POLICY_UNREADABLE], report
    assert report["run_id"] == "run"
    vr.report_schema_validator().validate(report)
    return report


def test_cli_broken_default_policy_replaces_stale_report(tmp_path):
    run = _write_good_run(tmp_path / "run")
    report_path = run / "reports" / "gate_report.json"
    _stale_accept(report_path)
    (run / "policy.json").write_text("{", encoding="utf-8")
    assert _main(["--run", str(run)]) == 1
    _assert_policy_reject(report_path)


def test_cli_broken_explicit_policy_gives_reject_report(tmp_path):
    run = _write_good_run(tmp_path / "run")
    out = tmp_path / "out.json"
    _stale_accept(out)
    bad = tmp_path / "policy.json"
    bad.write_text(json.dumps({"waivers": "NEG.QA.SLOW"}), encoding="utf-8")
    assert _main(["--run", str(run), "--out", str(out), "--policy", str(bad)]) == 1
    _assert_policy_reject(out)


def test_cli_unlistable_run_dir_gives_reject_report(tmp_path, monkeypatch):
    # Simulates NTFS "icacls deny RD" on every host: listing the run dir fails.
    run = _write_good_run(tmp_path / "run")
    out = tmp_path / "out.json"
    _stale_accept(out)
    real_listdir = os.listdir
    target = os.path.normcase(os.path.abspath(run))

    def listdir(path="."):
        if os.path.normcase(os.path.abspath(os.fspath(path))) == target:
            raise PermissionError(13, "Access is denied", os.fspath(path))
        return real_listdir(path)

    monkeypatch.setattr(vr.os, "listdir", listdir)
    assert _main(["--run", str(run), "--out", str(out)]) == 1
    _assert_policy_reject(out)


def test_api_still_raises_policy_error_for_unreadable_policy(tmp_path):
    # Documented API contract (docs/API.md "Errors"): only the CLI converts.
    run = _write_good_run(tmp_path / "run")
    (run / "policy.json").write_text("{", encoding="utf-8")
    try:
        vr.validate_run(str(run))
    except Exception as exc:  # noqa: BLE001 - the exception TYPE is the assertion
        assert type(exc) is vr.PolicyError, type(exc)
    else:
        raise AssertionError("validate_run accepted an unreadable policy")


def test_cli_process_broken_policy_no_traceback(tmp_path):
    """Real process, real __main__ wiring: rc != 0, no traceback, REJECT on disk."""
    import subprocess

    run = _write_good_run(tmp_path / "run")
    report_path = run / "reports" / "gate_report.json"
    _stale_accept(report_path)
    (run / "policy.json").write_text("{", encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(ROOT / "TOOLS" / "validate_run.py"), "--run", str(run)],
        capture_output=True, text=True, stdin=subprocess.DEVNULL, check=False,
    )
    assert proc.returncode == 1, (proc.returncode, proc.stderr)
    assert "Traceback" not in proc.stderr, proc.stderr
    assert "policy error" in proc.stderr
    _assert_policy_reject(report_path)


def test_policy_unreadable_is_hard_and_not_waivable():
    sm = importlib.import_module("severity_mapping")
    for lever in ({"waived_issue_ids": [POLICY_UNREADABLE]},
                  {"known_issue_ids": [POLICY_UNREADABLE]}):
        assert sm.classify_neg_id(POLICY_UNREADABLE, {}, **lever) == "HARD_FAIL"
    try:
        vr.validate_policy_shape({"waivers": [POLICY_UNREADABLE]})
    except Exception as exc:  # noqa: BLE001
        assert type(exc) is vr.PolicyError, type(exc)
    else:
        raise AssertionError("a policy waiving NEG.POLICY.UNREADABLE was accepted")


def test_cli_unwritable_output_is_rc1_without_traceback(tmp_path):
    run = _write_good_run(tmp_path / "run")
    blocker = tmp_path / "blocker"
    blocker.write_text("a file, not a directory", encoding="utf-8")
    assert _main(["--run", str(run), "--out", str(blocker / "sub" / "out.json")]) == 1


@pytest.mark.parametrize("fail_at", ["open", "dump"])
def test_cli_write_failure_removes_stale_report(tmp_path, monkeypatch, capsys, fail_at):
    # Host-independent simulation of the POSIX branch: the report cannot be written
    # (read-only old report -> open fails; disk full -> dump fails after truncation),
    # the old report is still removable, so no older ACCEPT may be left behind.
    run = _write_good_run(tmp_path / "run")
    report_path = run / "reports" / "gate_report.json"
    _stale_accept(report_path)
    (run / "policy.json").write_text("{", encoding="utf-8")
    target = os.path.normcase(os.path.abspath(report_path))

    if fail_at == "open":
        real_open = open

        def fake_open(file, mode="r", *args, **kwargs):
            if "w" in mode and os.path.normcase(os.path.abspath(os.fspath(file))) == target:
                raise PermissionError(13, "Permission denied", os.fspath(file))
            return real_open(file, mode, *args, **kwargs)

        monkeypatch.setattr(vr, "open", fake_open, raising=False)
    else:
        def fake_dump(*args, **kwargs):
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(vr.json, "dump", fake_dump)

    assert _main(["--run", str(run)]) == 1
    assert "cannot write report" in capsys.readouterr().err
    assert not report_path.exists(), (
        "write failed but a report is still standing at the output path: "
        + report_path.read_text(encoding="utf-8")[:200]
    )


def test_cli_readonly_stale_report_real_filesystem(tmp_path, capsys):
    # Real permissions, no monkeypatch. POSIX (non-root): the directory is writable, so
    # the read-only old ACCEPT is removed. Windows: a read-only file cannot be deleted
    # either -- it may stay (docs/API.md "where possible"), but the exit code stays 1.
    import stat

    if sys.platform != "win32" and hasattr(os, "geteuid") and os.geteuid() == 0:
        pytest.skip("root ignores file permissions; open() on a 0444 file succeeds")
    run = _write_good_run(tmp_path / "run")
    report_path = run / "reports" / "gate_report.json"
    _stale_accept(report_path)
    (run / "policy.json").write_text("{", encoding="utf-8")
    os.chmod(report_path, stat.S_IRUSR)
    try:
        assert _main(["--run", str(run)]) == 1
        assert "cannot write report" in capsys.readouterr().err
        if sys.platform != "win32":
            assert not report_path.exists(), "stale ACCEPT survived on POSIX"
    finally:
        if report_path.exists():
            os.chmod(report_path, stat.S_IRUSR | stat.S_IWUSR)


def test_cli_out_without_directory_part(tmp_path, monkeypatch):
    # os.makedirs("") used to raise FileNotFoundError for "--out report.json".
    run = _write_good_run(tmp_path / "run")
    monkeypatch.chdir(tmp_path)
    assert _main(["--run", str(run), "--out", "report.json"]) == 0
    assert json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))["status"] == "ACCEPT"


def test_cli_good_run_still_rc0(tmp_path):
    run = _write_good_run(tmp_path / "run")
    out = tmp_path / "out.json"
    assert _main(["--run", str(run), "--out", str(out)]) == 0
    assert json.loads(out.read_text(encoding="utf-8"))["status"] == "ACCEPT"


# --------------------- #35 type hardening outside the CLI ------------------- #
rf = importlib.import_module("root_finding")
sm35 = importlib.import_module("severity_mapping")


@pytest.mark.parametrize("method", [[], ["brentq"], {"brentq"}, {"m": 1}, None, 3, b"brentq"])
def test_find_root_bracketed_bad_method_type_never_raises(method):
    try:
        res = rf.find_root_bracketed(lambda x: x - 1.0, (0.0, 2.0), method=method)
    except Exception as exc:  # noqa: BLE001 - docs/API.md: solver failures never raise
        raise AssertionError(f"raised {type(exc).__name__}: {exc}") from exc
    assert res.converged is False and res.root is None
    assert res.message == "unknown method"
    assert isinstance(res.method, str)


def test_find_root_bracketed_valid_method_unchanged():
    res = rf.find_root_bracketed(lambda x: x - 1.0, (0.0, 2.0), method="brentq")
    assert res.converged is True and abs(res.root - 1.0) < 1e-9 and res.method == "brentq"


@pytest.mark.parametrize("lever", ["waived_issue_ids", "known_issue_ids"])
@pytest.mark.parametrize("ids", ["NEG.QA.SLOWNESS", b"NEG.QA.SLOWNESS", (i for i in ["NEG.QA.SLOW"]), None])
def test_classify_rejects_non_collection_levers(lever, ids):
    try:
        cls = sm35.classify_neg_id("NEG.QA.SLOW", {}, **{lever: ids})
    except Exception as exc:  # noqa: BLE001 - the exception TYPE is the assertion
        assert type(exc) is ValueError, f"{type(exc).__name__}: {exc}"
    else:
        raise AssertionError(f"{lever}={ids!r} accepted, classified as {cls}")


@pytest.mark.parametrize("container", [list, tuple, set, frozenset])
def test_classify_collection_levers_still_work(container):
    assert sm35.classify_neg_id("NEG.QA.SLOW", {}, waived_issue_ids=container(["NEG.QA.SLOWNESS"])) == "SOFT_FAIL"
    assert sm35.classify_neg_id("NEG.QA.SLOW", {}, waived_issue_ids=container(["NEG.QA.SLOW"])) == "WAIVED_ISSUE"
    assert sm35.classify_neg_id("NEG.QA.SLOW", {}, known_issue_ids=container(["NEG.QA.SLOW"])) == "KNOWN_ISSUE"
