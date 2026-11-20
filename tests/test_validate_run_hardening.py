"""Regression tests for validate_run hardening (issue #18).

Covers: explicit policy loading + fail-closed on malformed policy,
non-downgradable override refusal, and enforced `format: date-time`.
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


# --------------------------- policy shape (fail-closed) --------------------- #
def test_validate_policy_shape_accepts_well_formed():
    policy = {
        "severity_overrides": {"NEG.QA.SLOW": "WARNING"},
        "known_issues": ["NEG.PROV.MISSING_GENERATION_EDGE"],
        "waivers": [],
    }
    assert vr.validate_policy_shape(policy) is policy


@pytest.mark.parametrize(
    "bad",
    [
        "not-a-dict",
        {"unexpected_key": 1},
        {"severity_overrides": "nope"},
        {"severity_overrides": {"NEG.X": "BOOM"}},
        {"severity_overrides": {"": "WARNING"}},
        {"known_issues": [1]},
        {"waivers": ["", "ok"]},
    ],
)
def test_validate_policy_shape_rejects_malformed(bad):
    with pytest.raises(vr.PolicyError):
        vr.validate_policy_shape(bad)


def test_policy_may_not_downgrade_non_downgradable_id():
    with pytest.raises(vr.PolicyError):
        vr.validate_policy_shape({"severity_overrides": {"NEG.ROOT.UNKNOWN_METHOD": "WARNING"}})


# --------------------------- load_policy (I/O) ------------------------------ #
def test_load_policy_missing_file_fails_closed(tmp_path):
    with pytest.raises(vr.PolicyError):
        vr.load_policy(str(tmp_path / "does_not_exist.json"))


def test_load_policy_invalid_json_fails_closed(tmp_path):
    p = tmp_path / "policy.json"
    p.write_text("{ not json", encoding="utf-8")
    with pytest.raises(vr.PolicyError):
        vr.load_policy(str(p))


def test_load_policy_roundtrip(tmp_path):
    p = tmp_path / "policy.json"
    p.write_text(json.dumps({"known_issues": ["NEG.PROV.X"]}), encoding="utf-8")
    assert vr.load_policy(str(p)) == {"known_issues": ["NEG.PROV.X"]}


# --------------------------- default policy discovery ----------------------- #
def _kernels(run: Path):
    kdir = run / "kernels"
    kdir.mkdir(parents=True)
    for name in ("model", "plan", "events", "schema", "env"):
        (kdir / f"kernel.{name}.json").write_text(
            json.dumps({"content_hash": "h", "version": "1.0.0", "payload": {}}),
            encoding="utf-8",
        )


def test_no_policy_file_preserves_default_behavior(tmp_path):
    run = tmp_path / "run"
    _kernels(run)
    report = vr.validate_run(str(run))  # no policy.json present
    assert report["status"] == "ACCEPT"


def test_default_policy_file_is_loaded_from_run_dir(tmp_path):
    run = tmp_path / "run"
    _kernels(run)
    # Force a report-schema break would be complex; instead prove a malformed
    # default policy fails closed (i.e. it is actually read from <run>/policy.json).
    (run / "policy.json").write_text(json.dumps({"oops": True}), encoding="utf-8")
    with pytest.raises(vr.PolicyError):
        vr.validate_run(str(run))


# --------------------------- date-time format enforcement ------------------- #
def test_report_validator_enforces_date_time_format():
    validator = vr.report_schema_validator()
    base = {
        "run_id": "r1",
        "created_utc": vr.utc_now(),
        "status": "ACCEPT",
        "hard_fail": [],
        "soft_fail": [],
        "warnings": [],
        "known_issues": [],
        "metrics": [],
        "gate_results": [],
    }
    assert list(validator.iter_errors(base)) == []

    bad = dict(base)
    bad["created_utc"] = "2026-07-05 00:00:00"  # space, no offset -> invalid RFC3339
    assert len(list(validator.iter_errors(bad))) >= 1

    bad2 = dict(base)
    bad2["created_utc"] = "not-a-date"
    assert len(list(validator.iter_errors(bad2))) >= 1


def test_format_checker_is_closed_world():
    """Only formats ARK registers itself are enforced, whatever packages are installed
    (CI has jsonschema[format] extras via cyclonedx-bom, a runtime install does not)."""
    assert set(vr.strict_format_checker().checkers) == {"date-time"}


@pytest.mark.parametrize("fmt, value", [
    ("ipv4", "not-an-ip"),       # stdlib checker: enforced by a plain FormatChecker() everywhere
    ("uri", "not a uri"),        # extras checker: enforced only where rfc3987-syntax is installed
    ("hostname", "-bad-.host"),  # extras checker (fqdn)
])
def test_unregistered_format_is_not_enforced_in_any_environment(fmt, value):
    from jsonschema import Draft202012Validator

    validator = Draft202012Validator({"type": "string", "format": fmt},
                                     format_checker=vr.strict_format_checker())
    assert validator.is_valid(value), f"format {fmt!r} enforced: verdict would depend on site-packages"


def _schema_formats(node):
    if isinstance(node, dict):
        if isinstance(node.get("format"), str):
            yield node["format"]
        for v in node.values():
            yield from _schema_formats(v)
    elif isinstance(node, list):
        for v in node:
            yield from _schema_formats(v)


def test_every_schema_format_is_registered():
    """Closed world must not mean silently unenforced: each `format` used in SCHEMAS/ is
    registered in strict_format_checker()."""
    registered = set(vr.strict_format_checker().checkers)
    for path in sorted((ROOT / "SCHEMAS").glob("*.json")):
        used = set(_schema_formats(json.loads(path.read_text(encoding="utf-8"))))
        assert used <= registered, f"{path.name}: unregistered formats {sorted(used - registered)}"


def test_generated_report_created_utc_passes_format_check():
    validator = vr.report_schema_validator()
    # utc_now() output must itself be a valid date-time (self-consistency).
    doc = {
        "run_id": "r",
        "created_utc": vr.utc_now(),
        "status": "ACCEPT",
        "hard_fail": [],
        "soft_fail": [],
        "warnings": [],
        "known_issues": [],
        "metrics": [],
        "gate_results": [],
    }
    validator.validate(doc)
