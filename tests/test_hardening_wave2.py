"""Regression tests for the spec-vs-code hardening wave 2.

Each test pins one defect that reproduced on main before the fix:

1. NON_DOWNGRADABLE ids could be softened via ``waivers`` / ``known_issues``
   (a downgrade path the severity-override guard did not cover).
2. A malformed kernel JSON crashed ``validate_run`` without emitting a report.
3. The contradiction DSL only shape-checked the root node: malformed nested
   expressions crashed (AttributeError) or slipped past a short-circuit.
4. ``provenance_validate`` ignored ``used`` / ``wasDerivedFrom`` edges although
   PROVENANCE_MINIMAL_v1 requires every referenced node id to exist.
5. ``event_hysteresis`` accepted a negative delta (inverted band).
6. ``NEG.ROOT.UNKNOWN_METHOD`` was unreachable through ``validate_run``: the
   method was read from a ``ROOT`` policy key that policy validation rejects.
   It is now read from ``kernel.plan.json`` (``payload.root.METHOD``).
7. ``NEG.KERNEL.*`` payload findings were waivable although missing kernel
   files are unroutable HARD failures; kernel integrity is now locked.
"""
from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "TOOLS"))

severity_mapping = importlib.import_module("severity_mapping")
validate_run = importlib.import_module("validate_run")
contradiction_rules = importlib.import_module("contradiction_rules")
provenance_validate = importlib.import_module("provenance_validate")
event_hysteresis = importlib.import_module("event_hysteresis")
root_finding = importlib.import_module("root_finding")

LOCKED = "NEG.ROOT.UNKNOWN_METHOD"


# --------------------------------------------------------------------------- #
# 1. NON_DOWNGRADABLE is immune to every policy lever
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("lever", ["waived", "known"])
def test_non_downgradable_ignores_waiver_and_known_issue(lever):
    kwargs = {"waived_issue_ids": [LOCKED]} if lever == "waived" else {"known_issue_ids": [LOCKED]}
    assert severity_mapping.classify_neg_id(LOCKED, {}, **kwargs) == "HARD_FAIL"


def test_downgradable_id_can_still_be_waived():
    assert (
        severity_mapping.classify_neg_id("NEG.QA.SLOW", {}, waived_issue_ids=["NEG.QA.SLOW"])
        == "WAIVED_ISSUE"
    )


@pytest.mark.parametrize("neg_id", ["NEG.QA.SLOW", LOCKED])
def test_invalid_override_value_is_rejected_by_classifier(neg_id):
    # Also for a locked id, whose (valid) override would merely be ignored.
    with pytest.raises(ValueError):
        severity_mapping.classify_neg_id(neg_id, {"severity_overrides": {neg_id: "PASS"}})


@pytest.mark.parametrize("key", ["waivers", "known_issues"])
def test_policy_refuses_waiving_non_downgradable(key):
    with pytest.raises(validate_run.PolicyError, match="non-downgradable"):
        validate_run.validate_policy_shape({key: [LOCKED]})


# --------------------------------------------------------------------------- #
# 2. malformed kernel payload -> HARD fail with a report, never a crash
# --------------------------------------------------------------------------- #
def _write_kernels(run_dir: Path) -> Path:
    kdir = run_dir / "kernels"
    kdir.mkdir(parents=True)
    for name in ("model", "plan", "events", "schema", "env"):
        (kdir / f"kernel.{name}.json").write_text(
            json.dumps({"content_hash": f"sha256:{name}", "version": "1.0.0", "payload": {}}),
            encoding="utf-8",
        )
    return kdir


@pytest.mark.parametrize("content", ["{not json", "[1, 2]", '"a string"'])
def test_unreadable_kernel_rejects_with_report(tmp_path, content):
    kdir = _write_kernels(tmp_path / "run")
    (kdir / "kernel.env.json").write_text(content, encoding="utf-8")
    report = validate_run.validate_run(str(tmp_path / "run"))
    assert report["status"] == "REJECT"
    assert report["hard_fail"] == ["NEG.KERNEL.UNREADABLE"]


def test_non_string_version_is_invalid_semver(tmp_path):
    kdir = _write_kernels(tmp_path / "run")
    (kdir / "kernel.env.json").write_text(
        json.dumps({"content_hash": "sha256:x", "version": 1, "payload": {}}), encoding="utf-8"
    )
    report = validate_run.validate_run(str(tmp_path / "run"))
    assert "NEG.KERNEL.INVALID_SEMVER" in report["hard_fail"]


# --------------------------------------------------------------------------- #
# 3. contradiction DSL: whole-tree structural validation
# --------------------------------------------------------------------------- #
def _codes(when, metrics=None):
    rule = {"rule_id": "R", "when": when, "neg_id": "NEG.CONTRADICTION.X",
            "severity": "WARNING", "summary": "s"}
    hits, issues = contradiction_rules.evaluate_rules([rule], metrics or {"METRIC.a": 1.0}, {})
    return {h.neg_id for h in hits}, {i.code for i in issues}


@pytest.mark.parametrize(
    "when, code",
    [
        ({"not": [1]}, "NEG.CONTRADICTION.INVALID_STRUCTURE"),
        ({"all": [5]}, "NEG.CONTRADICTION.INVALID_STRUCTURE"),
        ({"any": [{"gt": ["METRIC.a"]}]}, "NEG.CONTRADICTION.INVALID_STRUCTURE"),
        ({"all": [{"gt": [0, 1]}, {"bogus": 1}]}, "NEG.CONTRADICTION.UNKNOWN_OPERATOR"),
        ({"gt": [True, 0]}, "NEG.CONTRADICTION.TYPE_MISMATCH"),
        ({"gt": ["not_a_metric", 0]}, "NEG.CONTRADICTION.TYPE_MISMATCH"),
        # JSON ints are unbounded; beyond double range -> issue, not OverflowError
        ({"all": [{"gt": [0, 1]}, {"gt": [10**400, 1]}]}, "NEG.CONTRADICTION.TYPE_MISMATCH"),
        ({"gt": [10**10000, 1]}, "NEG.CONTRADICTION.TYPE_MISMATCH"),
    ],
)
def test_contradiction_nested_malformed_is_reported_not_crashing(when, code):
    hits, issues = _codes(when)
    assert hits == set()
    assert code in issues


def test_contradiction_valid_nested_rule_still_fires():
    hits, issues = _codes({"not": {"any": [{"lt": ["METRIC.a", 0]}, {"eq": ["METRIC.a", 2]}]}})
    assert issues == set()
    assert hits == {"NEG.CONTRADICTION.X"}


def test_contradiction_non_object_rule_is_structural_issue():
    hits, issues = contradiction_rules.evaluate_rules(["nope"], {}, {})
    assert hits == [] and {i.code for i in issues} == {"NEG.CONTRADICTION.INVALID_STRUCTURE"}


# --------------------------------------------------------------------------- #
# 4. provenance: every edge type is reference-checked in PROV-DM direction
# --------------------------------------------------------------------------- #
def _prov(extra_edges=(), extra_entities=()):
    return {
        "entities": [{"id": "e:out", "kind": "k"}, *extra_entities],
        "activities": [{"id": "a:run", "kind": "k"}],
        "agents": [{"id": "g:ark", "kind": "k"}],
        "edges": [
            {"type": "wasGeneratedBy", "src": "e:out", "dst": "a:run"},
            {"type": "wasAssociatedWith", "src": "a:run", "dst": "g:ark"},
            *extra_edges,
        ],
    }


def test_prov_valid_used_and_derived_edges_pass():
    doc = _prov(
        extra_entities=[{"id": "e:in", "kind": "k"}],
        extra_edges=[
            {"type": "wasGeneratedBy", "src": "e:in", "dst": "a:run"},
            {"type": "used", "src": "a:run", "dst": "e:in"},
            {"type": "wasDerivedFrom", "src": "e:out", "dst": "e:in"},
        ],
    )
    assert provenance_validate.validate_prov_min(doc) == []


@pytest.mark.parametrize(
    "edge",
    [
        {"type": "used", "src": "a:run", "dst": "e:ghost"},
        {"type": "used", "src": "e:out", "dst": "a:run"},  # reversed direction
        {"type": "wasDerivedFrom", "src": "e:out", "dst": "g:ark"},  # agent is no entity
        {"type": "wasGeneratedBy", "src": ["e:out"], "dst": "a:run"},  # unhashable ref
    ],
)
def test_prov_broken_ref_on_any_edge_type(edge):
    assert "NEG.PROV.BROKEN_REF" in provenance_validate.validate_prov_min(_prov([edge]))


def test_prov_unknown_edge_type_and_duplicate_and_missing_id():
    doc = _prov([{"type": "wasInformedBy", "src": "a:run", "dst": "a:run"}])
    doc["agents"].append({"id": "e:out", "kind": "k"})
    doc["activities"].append({"kind": "no-id"})
    negs = provenance_validate.validate_prov_min(doc)
    assert {"NEG.PROV.UNKNOWN_EDGE_TYPE", "NEG.PROV.DUPLICATE_ID", "NEG.PROV.MISSING_ID"} <= set(negs)


# --------------------------------------------------------------------------- #
# 5. hysteresis parameters
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "kwargs",
    [{"delta": -0.1}, {"delta": float("nan")}, {"delta": 0.1, "min_support": 0},
     {"delta": 0.1, "min_duration": -1.0}],
)
def test_hysteresis_rejects_invalid_parameters(kwargs):
    with pytest.raises(ValueError):
        event_hysteresis.hysteresis_windows([0.0, 1.0], [0.0, 1.0], threshold=0.5, **kwargs)


# --------------------------------------------------------------------------- #
# 6. root-finding method is pinned in kernel.plan.json and enforced
# --------------------------------------------------------------------------- #
def _set_plan_root(kdir: Path, root) -> None:
    plan = {"content_hash": "sha256:plan", "version": "1.0.0", "payload": {"kind": "plan"}}
    if root is not _ABSENT:
        plan["payload"]["root"] = root
    (kdir / "kernel.plan.json").write_text(json.dumps(plan), encoding="utf-8")


_ABSENT = object()


@pytest.mark.parametrize("root", [{"METHOD": "newton"}, {"METHOD": 3}, "brentq", None, {}])
def test_unknown_or_malformed_plan_root_method_rejects(tmp_path, root):
    kdir = _write_kernels(tmp_path / "run")
    _set_plan_root(kdir, root)
    report = validate_run.validate_run(str(tmp_path / "run"))
    assert report["status"] == "REJECT"
    assert report["hard_fail"] == ["NEG.ROOT.UNKNOWN_METHOD"]


@pytest.mark.parametrize("root", [_ABSENT, {"METHOD": "toms748"}])
def test_allowed_or_default_plan_root_method_accepts(tmp_path, root):
    kdir = _write_kernels(tmp_path / "run")
    _set_plan_root(kdir, root)
    assert validate_run.validate_run(str(tmp_path / "run"))["status"] == "ACCEPT"


def test_unknown_root_method_cannot_be_waived_via_policy_file(tmp_path):
    kdir = _write_kernels(tmp_path / "run")
    _set_plan_root(kdir, {"METHOD": "newton"})
    (tmp_path / "run" / "policy.json").write_text(json.dumps({"waivers": [LOCKED]}), encoding="utf-8")
    with pytest.raises(validate_run.PolicyError):
        validate_run.validate_run(str(tmp_path / "run"))


def test_root_method_allowlists_do_not_drift():
    # validate_run keeps its own copy to stay importable without SciPy.
    assert validate_run.ROOT_ALLOWED_METHODS == root_finding.ROOT_ALLOWED_METHODS


# --------------------------------------------------------------------------- #
# 7. kernel integrity findings are non-downgradable
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("neg_id", ["NEG.KERNEL.INVALID_SEMVER", "NEG.KERNEL.UNREADABLE",
                                    "NEG.KERNEL.MISSING_HASH"])
def test_kernel_findings_are_locked(neg_id):
    assert severity_mapping.is_non_downgradable(neg_id)
    assert severity_mapping.classify_neg_id(
        neg_id, {"severity_overrides": {neg_id: "WARNING"}},
        known_issue_ids=[neg_id], waived_issue_ids=[neg_id]) == "HARD_FAIL"
    with pytest.raises(validate_run.PolicyError, match="non-downgradable"):
        validate_run.validate_policy_shape({"waivers": [neg_id]})


def test_other_hard_prefixes_stay_waivable():
    # Only kernel integrity is locked; e.g. a deprecated-plugin contract finding
    # remains an explicit, reviewable waiver decision.
    neg_id = "NEG.CONTRACT.DEPRECATED_PLUGIN_USED"
    assert not severity_mapping.is_non_downgradable(neg_id)
    assert severity_mapping.classify_neg_id(neg_id, {}, waived_issue_ids=[neg_id]) == "WAIVED_ISSUE"
    validate_run.validate_policy_shape({"waivers": [neg_id]})
