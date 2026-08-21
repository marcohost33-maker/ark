from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIXTURE = HERE / "fixtures" / "dde_scalar_linear_real.json"
spec = importlib.util.spec_from_file_location("ark_rc_normalize", HERE / "normalize.py")
assert spec is not None and spec.loader is not None
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def load_fixture():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def codes(result):
    return {x["code"] for x in result["contradictions"]}


def test_real_dde_fixture_normalizes_without_blocker():
    result = mod.normalize(load_fixture())
    assert result["blocking"] is False
    assert result["contradictions"] == []
    assert result["input_digest"].startswith("sha256:")
    assert result["output_digest"].startswith("sha256:")
    assert result["schema_version"] == "1.1.0-candidate"
    assert len(result["records"]) == 3
    assert result["trust_boundary"].endswith("not scientific truth.")


def test_output_digest_is_stable_for_identical_input():
    fixture = load_fixture()
    a = mod.normalize(fixture)
    b = mod.normalize(copy.deepcopy(fixture))
    assert a == b
    assert a["input_digest"] == b["input_digest"]
    assert a["output_digest"] == b["output_digest"]


def test_output_digest_binds_claim_and_run_content():
    fixture = load_fixture()
    a = mod.normalize(fixture)
    changed = copy.deepcopy(fixture)
    changed["run_plan"]["tolerances"]["atol"] = 0.0006
    b = mod.normalize(changed)
    assert a["input_digest"] != b["input_digest"]
    assert a["contract_bindings"]["run_plan_digest"] != b["contract_bindings"]["run_plan_digest"]
    assert a["output_digest"] != b["output_digest"]


def test_source_ids_revisions_and_digests_are_preserved():
    fixture = load_fixture()
    result = mod.normalize(fixture)
    source = fixture["evidence_attestations"][0]
    rec = next(r for r in result["records"] if r["source_id"] == source["evidence_id"])
    assert rec["source_revision"] == source["source_revision"]
    assert rec["material_digest"] == source["material_digest"]
    assert rec["source_object"] == source


def test_stale_pass_evidence_blocks_and_invalidates_pass_gate():
    fixture = load_fixture()
    fixture["evidence_attestations"][0]["stale"] = True
    result = mod.normalize(fixture)
    assert result["blocking"] is True
    assert "RC.EVIDENCE.STALE" in codes(result)
    assert "RC.GATE.PASS_WITH_BLOCKING_CONTRADICTION" in codes(result)


def test_missing_explicit_freshness_is_fail_closed():
    fixture = load_fixture()
    fixture["evidence_attestations"][0].pop("stale")
    result = mod.normalize(fixture)
    assert "RC.EVIDENCE.STALE" in codes(result)


def test_unavailable_evidence_cannot_be_promoted():
    fixture = load_fixture()
    fixture["evidence_attestations"][0]["verdict"] = "UNAVAILABLE"
    result = mod.normalize(fixture)
    assert "RC.EVIDENCE.NON_PASS" in codes(result)


def test_unbound_evidence_blocks():
    fixture = load_fixture()
    fixture["evidence_attestations"][0]["subject"]["run_id"] = "RUN-WRONG"
    result = mod.normalize(fixture)
    assert "RC.EVIDENCE.UNBOUND" in codes(result)


def test_missing_provenance_binding_blocks():
    fixture = load_fixture()
    fixture["evidence_attestations"][0].pop("material_digest")
    result = mod.normalize(fixture)
    assert "RC.EVIDENCE.PROVENANCE_INCOMPLETE" in codes(result)
    assert "RC.EVIDENCE.DIGEST_INVALID" in codes(result)


def test_top_level_required_provenance_fields_are_enforced():
    fixture = load_fixture()
    fixture["provenance_fields"] = ["source_revision", "material_digest", "environment"]
    fixture["evidence_attestations"][0].pop("environment")
    result = mod.normalize(fixture)
    assert "RC.EVIDENCE.PROVENANCE_INCOMPLETE" in codes(result)


def test_source_revision_must_match_run_code_revision():
    fixture = load_fixture()
    fixture["evidence_attestations"][0]["source_revision"] = "deadbeef"
    result = mod.normalize(fixture)
    assert "RC.EVIDENCE.SOURCE_REVISION_MISMATCH" in codes(result)
    assert "RC.GATE.PASS_WITH_BLOCKING_CONTRADICTION" in codes(result)


def test_duplicate_evidence_ids_block_unambiguous_binding():
    fixture = load_fixture()
    fixture["evidence_attestations"].append(copy.deepcopy(fixture["evidence_attestations"][0]))
    result = mod.normalize(fixture)
    assert "RC.EVIDENCE.DUPLICATE_ID" in codes(result)


def test_required_oracle_must_have_current_passing_bound_evidence():
    fixture = load_fixture()
    fixture["run_plan"]["required_oracles"] = ["dde-analytic-reference", "independent-oracle-B"]
    result = mod.normalize(fixture)
    assert "RC.ORACLE.MISSING" in codes(result)


def test_pass_gate_must_bind_claim_and_have_valid_digest():
    fixture = load_fixture()
    fixture["gate_reports"][0]["subject_id"] = "CLM-WRONG"
    fixture["gate_reports"][0]["input_digest"] = "not-a-digest"
    result = mod.normalize(fixture)
    assert "RC.GATE.UNBOUND" in codes(result)
    assert "RC.GATE.INPUT_DIGEST_INVALID" in codes(result)


def test_supersession_failure_and_stale_dependency_are_blocking():
    fixture = load_fixture()
    fixture["supersession_reports"] = [{
        "report_id": "SUPER-DDE-001",
        "type": "SupersessionReport",
        "result": "FAIL",
        "valid": False,
        "stale_dependencies": ["CLM-OLD-001"],
        "source_revision": "deadbeef",
    }]
    result = mod.normalize(fixture)
    assert "RC.SUPERSESSION.FAIL" in codes(result)
    assert "RC.SUPERSESSION.STALE_DEPENDENCY" in codes(result)


def test_record_order_is_normalized_even_when_input_evidence_order_changes():
    fixture = load_fixture()
    a = mod.normalize(fixture)
    fixture["evidence_attestations"].reverse()
    b = mod.normalize(fixture)
    assert a["records"] == b["records"]
    # The input digest intentionally binds the exact JSON input, including array order.
    assert a["input_digest"] != b["input_digest"]
    assert a["output_digest"] != b["output_digest"]
