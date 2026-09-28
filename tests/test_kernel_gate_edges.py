"""Regression tests for two kernel-gate edges found in review of #32.

A1. Kernel file names must match EXACTLY (case-sensitive). ``check_kernel_files``
    used ``os.path.exists``, which ignores case on Windows/macOS default file
    systems, while the payload loop compared names case-sensitively. A run with
    ``kernels/kernel.PLAN.json`` (root.METHOD = newton) was therefore ACCEPTed on
    a case-insensitive FS: the plan counted as present, but its root method was
    never checked. The tests below simulate a case-insensitive FS by patching
    ``os.path.exists`` / ``os.listdir`` inside ``validate_run``, so they bite on
    every platform (Linux CI included), plus one probe on the public CLI.

A3. A kernel file that ``json`` cannot materialise -- an integer literal beyond
    Python's int-digit limit (``ValueError``) or nesting deep enough to exhaust
    the recursion limit (``RecursionError``) -- crashed ``validate_run`` without a
    report. Both must now be REJECT with ``NEG.KERNEL.UNREADABLE``.
"""
from __future__ import annotations

import importlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "TOOLS"))

validate_run = importlib.import_module("validate_run")

CASE = "NEG.KERNEL.NAME_CASE_MISMATCH"
GOOD = {"content_hash": "sha256:x", "version": "1.0.0", "payload": {}}
NAMES = ("model", "plan", "events", "schema", "env")


def _write_run(run_dir: Path, files: dict) -> Path:
    kdir = run_dir / "kernels"
    kdir.mkdir(parents=True)
    for fn, content in files.items():
        text = content if isinstance(content, str) else json.dumps(content)
        (kdir / fn).write_text(text, encoding="utf-8")
    return run_dir


def _validate(run: Path) -> dict:
    """The contract is "a report, never an exception": a raise is a test verdict."""
    try:
        return validate_run.validate_run(str(run))
    except Exception as exc:
        raise AssertionError(f"validate_run crashed without a report: {type(exc).__name__}: {exc}"[:300]) from exc


def _base_files() -> dict:
    return {f"kernel.{n}.json": dict(GOOD) for n in NAMES}


def _simulate_case_insensitive_fs(monkeypatch, real_names_by_dir):
    """Make ``validate_run`` see a case-insensitive FS, whatever the host FS is.

    ``real_names_by_dir`` maps a kernels dir to the names stored on "disk".
    ``os.path.exists`` answers case-insensitively (as NTFS/APFS do) and
    ``os.listdir`` returns the stored spelling (as NTFS/APFS do).
    """
    real_exists = os.path.exists
    real_listdir = os.listdir

    def exists(path):
        d, base = os.path.split(os.fspath(path))
        names = real_names_by_dir.get(os.path.normcase(os.path.abspath(d)))
        if names is not None:
            return base.casefold() in {n.casefold() for n in names}
        return real_exists(path)

    def listdir(path="."):
        names = real_names_by_dir.get(os.path.normcase(os.path.abspath(os.fspath(path))))
        return list(names) if names is not None else real_listdir(path)

    monkeypatch.setattr(validate_run.os.path, "exists", exists)
    monkeypatch.setattr(validate_run.os, "listdir", listdir)


# --------------------------------------------------------------------------- #
# A1 -- exact, case-sensitive kernel file names
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "variant, content",
    [
        ("kernel.PLAN.json", dict(GOOD, payload={"root": {"METHOD": "newton"}})),
        ("KERNEL.plan.json", {}),
        ("Kernel.Plan.JSON", dict(GOOD)),
    ],
)
def test_case_variant_plan_is_rejected_on_case_insensitive_fs(tmp_path, monkeypatch, variant, content):
    files = _base_files()
    del files["kernel.plan.json"]
    files[variant] = content
    run = _write_run(tmp_path / "run", files)
    kdir = os.path.normcase(os.path.abspath(run / "kernels"))
    _simulate_case_insensitive_fs(monkeypatch, {kdir: sorted(files)})

    report = _validate(run)

    assert report["status"] == "REJECT"
    assert "NEG.KERNEL.MISSING_PLAN" in report["hard_fail"]
    assert CASE in report["hard_fail"]


def test_case_duplicate_next_to_exact_name_is_rejected(tmp_path, monkeypatch):
    # Case-sensitive FS (Linux) can hold both spellings; the variant must not
    # ride along unchecked next to a benign exact-name plan.
    files = _base_files()
    run = _write_run(tmp_path / "run", files)
    kdir = os.path.normcase(os.path.abspath(run / "kernels"))
    stored = sorted([*files, "kernel.PLAN.json"])
    real_listdir = os.listdir
    monkeypatch.setattr(
        validate_run.os,
        "listdir",
        lambda p=".": stored if os.path.normcase(os.path.abspath(os.fspath(p))) == kdir else real_listdir(p),
    )

    report = _validate(run)

    assert report["status"] == "REJECT"
    assert CASE in report["hard_fail"]
    assert "NEG.KERNEL.MISSING_PLAN" not in report["hard_fail"]


def test_case_variant_kernels_dir_is_missing_on_every_fs(tmp_path, monkeypatch):
    # Simulates NTFS/APFS: the dir is stored as "Kernels" but "kernels" resolves.
    run = _write_run(tmp_path / "run", _base_files())
    run_key = os.path.normcase(os.path.abspath(run))
    real_listdir = os.listdir
    monkeypatch.setattr(
        validate_run.os,
        "listdir",
        lambda p=".": ["Kernels"] if os.path.normcase(os.path.abspath(os.fspath(p))) == run_key else real_listdir(p),
    )

    report = _validate(run)

    assert report["status"] == "REJECT"
    assert sorted(report["hard_fail"]) == sorted(
        "NEG.KERNEL.MISSING_" + n.upper() for n in NAMES
    )


def test_exact_names_still_accept(tmp_path):
    run = _write_run(tmp_path / "run", _base_files())
    report = _validate(run)
    assert report["status"] == "ACCEPT"
    assert report["hard_fail"] == []


def test_non_kernel_files_are_ignored(tmp_path):
    files = _base_files()
    files["README.txt"] = "notes"
    files["other.PLAN.json"] = {}
    run = _write_run(tmp_path / "run", files)
    report = _validate(run)
    assert report["status"] == "ACCEPT"


@pytest.mark.parametrize("variant", ["KERNEL.custom.json", "kernel.custom.JSON"])
def test_case_variant_extra_kernel_file_is_rejected(tmp_path, variant):
    # Not a required name, but a kernel file once case is ignored: the payload
    # loop would skip it (case-sensitive prefix/suffix), so it must not pass.
    files = _base_files()
    files[variant] = {}
    run = _write_run(tmp_path / "run", files)
    report = _validate(run)
    assert report["status"] == "REJECT"
    assert report["hard_fail"] == [CASE]


def test_extra_lowercase_kernel_file_still_accepts(tmp_path):
    # No over-blocking: an additional, exactly-spelled kernel file is fine.
    files = _base_files()
    files["kernel.custom.json"] = dict(GOOD)
    run = _write_run(tmp_path / "run", files)
    assert _validate(run)["status"] == "ACCEPT"


def test_check_kernel_files_flags_case_duplicates_of_extra_files():
    names = [f"kernel.{n}.json" for n in NAMES] + ["kernel.custom.json", "kernel.CUSTOM.json"]
    assert validate_run.check_kernel_files("unused", names) == [CASE]
    exact = [f"kernel.{n}.json" for n in NAMES]
    assert validate_run.check_kernel_files("unused", exact) == []
    assert validate_run.check_kernel_files("unused", exact + ["kernel.plan.JSON"]) == [CASE]


def test_case_mismatch_is_not_downgradable(tmp_path):
    with pytest.raises(validate_run.PolicyError, match="non-downgradable"):
        validate_run.validate_policy_shape({"waivers": [CASE]})


def test_unlistable_kernels_dir_rejects_with_report(tmp_path, monkeypatch):
    run = _write_run(tmp_path / "run", _base_files())
    kdir = os.path.normcase(os.path.abspath(run / "kernels"))
    real_listdir = os.listdir

    def listdir(p="."):
        if os.path.normcase(os.path.abspath(os.fspath(p))) == kdir:
            raise PermissionError(13, "denied", str(p))
        return real_listdir(p)

    monkeypatch.setattr(validate_run.os, "listdir", listdir)
    report = _validate(run)
    assert report["status"] == "REJECT"
    assert "NEG.KERNEL.UNREADABLE" in report["hard_fail"]


def test_cli_rejects_case_variant_plan(tmp_path):
    """Public entry point, real host FS: kernel.PLAN.json must never be ACCEPT."""
    files = _base_files()
    del files["kernel.plan.json"]
    files["kernel.PLAN.json"] = dict(GOOD, payload={"root": {"METHOD": "newton"}})
    run = _write_run(tmp_path / "run", files)
    out = tmp_path / "out.json"
    proc = subprocess.run(
        [sys.executable, str(ROOT / "TOOLS" / "validate_run.py"), "--run", str(run), "--out", str(out)],
        capture_output=True, text=True, stdin=subprocess.DEVNULL, check=False,
    )
    assert proc.returncode == 0, proc.stderr
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["status"] == "REJECT"
    assert CASE in report["hard_fail"]
    assert "NEG.KERNEL.MISSING_PLAN" in report["hard_fail"]


# --------------------------------------------------------------------------- #
# A3 -- json materialisation limits -> REJECT with report, never a crash
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "content",
    [
        '{"content_hash":"x","version":"1.0.0","payload":' + "9" * 5000 + "}",
        "[" * 200000 + "]" * 200000,
        '{"a":' * 200000 + "1" + "}" * 200000,
    ],
    ids=["int_5000_digits", "deep_list_nesting", "deep_object_nesting"],
)
def test_unmaterialisable_kernel_rejects_with_report(tmp_path, content):
    files = _base_files()
    files["kernel.env.json"] = content
    run = _write_run(tmp_path / "run", files)
    report = _validate(run)
    assert report["status"] == "REJECT"
    assert report["hard_fail"] == ["NEG.KERNEL.UNREADABLE"]


def test_cli_unmaterialisable_kernel_writes_report(tmp_path):
    files = _base_files()
    files["kernel.plan.json"] = "[" * 200000 + "]" * 200000
    files["kernel.env.json"] = '{"content_hash":"x","version":"1.0.0","payload":' + "9" * 5000 + "}"
    run = _write_run(tmp_path / "run", files)
    out = tmp_path / "out.json"
    proc = subprocess.run(
        [sys.executable, str(ROOT / "TOOLS" / "validate_run.py"), "--run", str(run), "--out", str(out)],
        capture_output=True, text=True, stdin=subprocess.DEVNULL, check=False,
    )
    assert proc.returncode == 0, proc.stderr
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["status"] == "REJECT"
    assert report["hard_fail"] == ["NEG.KERNEL.UNREADABLE", "NEG.KERNEL.UNREADABLE"]


@pytest.mark.parametrize(
    "content",
    ['{"waivers":' + "9" * 5000 + "}", "[" * 200000 + "]" * 200000],
    ids=["int_5000_digits", "deep_nesting"],
)
def test_unmaterialisable_policy_is_policy_error(tmp_path, content):
    path = tmp_path / "policy.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(Exception) as excinfo:
        validate_run.load_policy(str(path))
    # Any other exception type is the crash this test guards against.
    assert isinstance(excinfo.value, validate_run.PolicyError), repr(excinfo.value)[:300]
    assert "unreadable" in str(excinfo.value)


# --- A1b: the default policy file must match EXACTLY as well -----------------


def test_policy_case_variant_is_not_loaded_on_case_insensitive_fs(tmp_path, monkeypatch):
    """``POLICY.json`` must not become the effective policy on NTFS/APFS while
    Linux ignores it. The stored file is unreadable, so loading it would raise."""
    run = _write_run(tmp_path / "run", _base_files())
    (run / "POLICY.json").write_text("{", encoding="utf-8")
    stored = {os.path.normcase(os.path.abspath(str(run))): sorted(os.listdir(run))}
    real_isfile = os.path.isfile

    def isfile(path):
        d, base = os.path.split(os.fspath(path))
        names = stored.get(os.path.normcase(os.path.abspath(d)))
        if names is not None:
            return base.casefold() in {n.casefold() for n in names}
        return real_isfile(path)

    monkeypatch.setattr(validate_run.os.path, "isfile", isfile)
    assert validate_run._resolve_policy(str(run), None) == {}


def test_policy_exact_name_is_still_loaded(tmp_path):
    run = _write_run(tmp_path / "run", _base_files())
    (run / "policy.json").write_text("{", encoding="utf-8")
    with pytest.raises(validate_run.PolicyError):
        validate_run._resolve_policy(str(run), None)


def test_unlistable_run_dir_fails_closed_not_crashing(tmp_path, monkeypatch):
    """Presence of policy.json is decided via os.listdir(run_dir); if that raises,
    validate_run must fail closed with PolicyError instead of crashing."""
    run = _write_run(tmp_path / "run", _base_files())
    real_listdir = os.listdir

    def listdir(path):
        if os.path.abspath(os.fspath(path)) == os.path.abspath(str(run)):
            raise PermissionError("denied")
        return real_listdir(path)

    monkeypatch.setattr(validate_run.os, "listdir", listdir)
    with pytest.raises(validate_run.PolicyError, match="not listable"):
        validate_run.validate_run(str(run))


@pytest.mark.parametrize("name", ["kernel.BASELINE.json", "kernel.Baseline.json"])
def test_case_variant_of_optional_spec_kernel_is_rejected(tmp_path, name):
    """kernel.baseline.json is spec-defined (BASELINE_POLICY_v1); a case variant of
    it must not pass as an arbitrary extra kernel."""
    run = _write_run(tmp_path / "run", _base_files())
    (run / "kernels" / name).write_text(json.dumps(GOOD), encoding="utf-8")
    report = validate_run.validate_run(str(run))
    assert report["status"] == "REJECT"
    assert CASE in report["hard_fail"]


def test_exact_optional_spec_kernel_is_accepted(tmp_path):
    run = _write_run(tmp_path / "run", _base_files())
    (run / "kernels" / "kernel.baseline.json").write_text(json.dumps(GOOD), encoding="utf-8")
    assert validate_run.validate_run(str(run))["status"] == "ACCEPT"
