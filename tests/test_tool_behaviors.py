"""Positive + negative behavioral tests for every ARK tool (issue #16).

Contract-mapped tools (`provenance_validate`, `severity_mapping`,
`contradiction_rules`, `validate_run`) are driven from reusable
`TESTVECTORS/**` fixtures asserting exact NEG IDs / statuses. Purely numeric
tools (`event_hysteresis`, `root_finding`) do not map to the status/neg_id
contract, so they are covered by direct behavioral assertions here.
No timing, randomness, or network is used.
"""
from __future__ import annotations

import importlib
import json
import math
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "TOOLS"
TESTVECTORS = ROOT / "TESTVECTORS"
sys.path.insert(0, str(TOOLS))

provenance_validate = importlib.import_module("provenance_validate")
severity_mapping = importlib.import_module("severity_mapping")
contradiction_rules = importlib.import_module("contradiction_rules")
event_hysteresis = importlib.import_module("event_hysteresis")
root_finding = importlib.import_module("root_finding")
validate_run = importlib.import_module("validate_run")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _status_from_negs(neg_ids, policy=None) -> str:
    """Mirror validate_run's worst-severity -> status routing (shared oracle)."""
    classes = [severity_mapping.classify_neg_id(n, policy or {}) for n in neg_ids]
    if "HARD_FAIL" in classes:
        return "REJECT"
    if "SOFT_FAIL" in classes:
        return "REVIEW"
    if any(c in ("WARNING", "KNOWN_ISSUE", "WAIVED_ISSUE") for c in classes):
        return "ACCEPT_WITH_NOTES"
    return "ACCEPT"


def _vectors(subdir: str):
    paths = sorted((TESTVECTORS / subdir).glob("*.json"))
    assert paths, f"no testvectors under TESTVECTORS/{subdir}"
    return [pytest.param(_load(p), id=p.stem) for p in paths]


# --------------------------------------------------------------------------- #
# provenance_validate — fixture-driven pos + neg
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("vec", _vectors("provenance"))
def test_provenance_behavior_vectors(vec):
    negs = provenance_validate.validate_prov_min(vec["inputs"]["prov"])
    assert sorted(negs) == sorted(vec["expected"]["neg_ids"])
    assert _status_from_negs(negs) == vec["expected"]["status"]


# --------------------------------------------------------------------------- #
# severity_mapping — fixture-driven pos + neg (incl. policy override)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("vec", _vectors("severity"))
def test_severity_behavior_vectors(vec):
    neg_ids = vec["inputs"]["neg_ids"]
    policy = vec.get("policy")
    assert neg_ids == vec["expected"]["neg_ids"]
    assert _status_from_negs(neg_ids, policy) == vec["expected"]["status"]


def test_severity_non_downgradable_ignores_override():
    """A NON_DOWNGRADABLE id stays HARD_FAIL even if a policy tries to soften it."""
    policy = {"severity_overrides": {"NEG.ROOT.UNKNOWN_METHOD": "WARNING"}}
    assert severity_mapping.classify_neg_id("NEG.ROOT.UNKNOWN_METHOD", policy) == "HARD_FAIL"


# --------------------------------------------------------------------------- #
# contradiction_rules — fixture-driven pos + neg
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("vec", _vectors("contradiction"))
def test_contradiction_behavior_vectors(vec):
    inp = vec["inputs"]
    hits, issues = contradiction_rules.evaluate_rules(inp["rules"], inp["metrics"], inp["baseline"])
    neg_ids = sorted({h.neg_id for h in hits} | {i.code for i in issues})
    assert neg_ids == sorted(vec["expected"]["neg_ids"])
    assert _status_from_negs(neg_ids) == vec["expected"]["status"]


# --------------------------------------------------------------------------- #
# validate_run — pos (valid run -> ACCEPT) + neg (bad semver -> REJECT)
# --------------------------------------------------------------------------- #
def _write_valid_kernels(run_dir: Path, version: str = "1.0.0") -> None:
    kdir = run_dir / "kernels"
    kdir.mkdir(parents=True)
    for name in ("model", "plan", "events", "schema", "env"):
        (kdir / f"kernel.{name}.json").write_text(
            json.dumps(
                {"content_hash": f"sha256:{name}", "version": version, "payload": {"kind": name}}
            ),
            encoding="utf-8",
        )


def test_validate_run_positive_clean_run_accepts(tmp_path):
    run = tmp_path / "good_run"
    _write_valid_kernels(run)
    report = validate_run.validate_run(str(run))
    assert report["status"] == "ACCEPT"
    assert report["hard_fail"] == []


def test_validate_run_negative_invalid_semver_rejects(tmp_path):
    run = tmp_path / "bad_semver_run"
    _write_valid_kernels(run, version="1.0")  # not SemVer 2.0.0
    report = validate_run.validate_run(str(run))
    assert report["status"] == "REJECT"
    assert "NEG.KERNEL.INVALID_SEMVER" in report["hard_fail"]


def test_validate_run_malformed_policy_fails_closed(tmp_path):
    run = tmp_path / "policy_run"
    _write_valid_kernels(run)
    (run / "policy.json").write_text('{"bogus_key": 1}', encoding="utf-8")
    with pytest.raises(validate_run.PolicyError):
        validate_run.validate_run(str(run))


# --------------------------------------------------------------------------- #
# event_hysteresis — pos (one window w/ support) + neg (length mismatch, no event)
# --------------------------------------------------------------------------- #
def test_event_hysteresis_positive_detects_window():
    t = [0.0, 1.0, 2.0, 3.0, 4.0]
    s = [0.0, 0.7, 0.8, 0.2, 0.0]  # threshold=0.5, delta=0.1: enter@i1, exit@i3
    windows = event_hysteresis.hysteresis_windows(t, s, threshold=0.5, delta=0.1, min_support=2)
    assert len(windows) == 1
    w = windows[0]
    assert (w.t_start, w.t_end) == (1.0, 2.0)
    assert w.support_count == 2
    assert w.reason == "hysteresis_fsm"


def test_event_hysteresis_negative_no_crossing_yields_no_window():
    t = [0.0, 1.0, 2.0]
    s = [0.0, 0.1, 0.2]  # never reaches threshold+delta
    assert event_hysteresis.hysteresis_windows(t, s, threshold=0.5, delta=0.1) == []


def test_event_hysteresis_negative_length_mismatch_raises():
    with pytest.raises(ValueError):
        event_hysteresis.hysteresis_windows([0.0, 1.0], [0.1], threshold=0.5, delta=0.1)


# --------------------------------------------------------------------------- #
# root_finding — pos (bracketed root) + neg (no sign change, unknown method)
# --------------------------------------------------------------------------- #
def test_root_finding_positive_converges_to_sqrt2():
    res = root_finding.find_root_bracketed(lambda x: x * x - 2.0, (0.0, 2.0), method="brentq")
    assert res.converged is True
    assert res.root is not None
    assert math.isclose(res.root, math.sqrt(2.0), rel_tol=1e-9)


def test_root_finding_negative_no_sign_change_bracket():
    res = root_finding.find_root_bracketed(lambda x: x * x - 2.0, (2.0, 3.0), method="brentq")
    assert res.converged is False
    assert res.root is None
    assert res.message == "no sign change bracket"


def test_root_finding_negative_unknown_method():
    res = root_finding.find_root_bracketed(lambda x: x - 1.0, (0.0, 2.0), method="newton")
    assert res.converged is False
    assert res.message == "unknown method"
