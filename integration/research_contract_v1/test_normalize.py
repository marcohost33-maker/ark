from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIXTURE = HERE / "fixtures" / "dde_scalar_linear_real.json"
POLICY = HERE / "policies" / "dde_producer_local_legacy_v1.json"
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import identity_policy as ident  # noqa: E402

spec = importlib.util.spec_from_file_location("ark_rc_normalize", HERE / "normalize.py")
assert spec is not None and spec.loader is not None
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def load_fixture():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def load_policy():
    return json.loads(POLICY.read_text(encoding="utf-8"))


def normalize(fixture=None, policy=None):
    return mod.normalize(
        load_fixture() if fixture is None else fixture,
        load_policy() if policy is None else policy,
    )


def codes(result):
    return {x["code"] for x in result["contradictions"]}


def independent_policy():
    p = {
        "schema_name": "ARKEvidenceIdentityPolicy",
        "schema_version": "1.0.0",
        "policy_id": "INDEPENDENT-EVIDENCE-v1",
        "policy_version": "1.0.0",
        "revision_binding": "INDEPENDENT_ALLOWED",
        "legacy_mode": "DISABLED",
        "oracle_authorizations": [],
        "legacy_verifier_versions": {},
        "notes": ["synthetic test policy"],
    }
    p["policy_digest"] = ident.policy_digest(p)
    return p


def convert_all_evidence_to_v1_1(fixture, *, evidence_revision="independent-evidence-rev-1"):
    run_revision = fixture["run_plan"]["code_revision"]
    for index, item in enumerate(fixture["evidence_attestations"]):
        item["schema_version"] = "1.1.0"
        item.pop("source_revision", None)
        item.pop("oracle_id", None)
        item["provenance"] = {
            "run_producer": {
                "id": "marcohost33-maker/coworker-dde",
                "revision": run_revision,
            },
            "evidence_producer": {
                "id": f"independent.example/evidence-{index}",
                "revision": f"{evidence_revision}-{index}",
            },
        }
        item["verifier"] = {
            "id": "dde-analytic-reference",
            "kind": "analytic-oracle",
            "implementation": {
                "id": f"independent-dde-oracle-{index}",
                "version": "2.0.0",
                "revision": f"oracle-implementation-rev-{index}",
            },
        }
        item["oracle_binding"] = {
            "oracle_id": "dde-analytic-reference",
            "mode": "DIRECT",
        }
    return fixture


def test_real_dde_fixture_normalizes_without_blocker():
    result = normalize()
    assert result["blocking"] is False
    assert result["contradictions"] == []
    assert result["input_digest"].startswith("sha256:")
    assert result["output_digest"].startswith("sha256:")
    assert result["schema_version"] == "1.2.0-candidate"
    assert len(result["records"]) == 3
    policy_binding = result["contract_bindings"]["evidence_identity_policy"]
    assert policy_binding["policy_id"] == "DDE-PRODUCER-LOCAL-LEGACY-v1"
    assert policy_binding["valid"] is True
    assert result["trust_boundary"].endswith("not scientific truth.")


def test_output_digest_is_stable_for_identical_input_and_policy():
    fixture = load_fixture()
    policy = load_policy()
    a = normalize(fixture, policy)
    b = normalize(copy.deepcopy(fixture), copy.deepcopy(policy))
    assert a == b
    assert a["input_digest"] == b["input_digest"]
    assert a["output_digest"] == b["output_digest"]


def test_output_digest_binds_claim_and_run_content():
    fixture = load_fixture()
    a = normalize(fixture)
    changed = copy.deepcopy(fixture)
    changed["run_plan"]["tolerances"]["atol"] = 0.0006
    b = normalize(changed)
    assert a["input_digest"] != b["input_digest"]
    assert a["contract_bindings"]["run_plan_digest"] != b["contract_bindings"]["run_plan_digest"]
    assert a["output_digest"] != b["output_digest"]


def test_source_ids_revisions_digests_and_verifier_identity_are_preserved_losslessly():
    fixture = load_fixture()
    result = normalize(fixture)
    source = fixture["evidence_attestations"][0]
    rec = next(r for r in result["records"] if r["source_id"] == source["evidence_id"])
    assert rec["source_revision"] == source["source_revision"]
    assert rec["material_digest"] == source["material_digest"]
    assert rec["identity"]["verifier"] == source["verifier"]
    assert rec["identity"]["legacy_oracle_id"] == source["oracle_id"]
    assert rec["source_object"] == source


def test_stale_pass_evidence_blocks_and_invalidates_pass_gate():
    fixture = load_fixture()
    fixture["evidence_attestations"][0]["stale"] = True
    result = normalize(fixture)
    assert result["blocking"] is True
    assert "RC.EVIDENCE.STALE" in codes(result)
    assert "RC.GATE.PASS_WITH_BLOCKING_CONTRADICTION" in codes(result)


def test_missing_explicit_freshness_is_fail_closed():
    fixture = load_fixture()
    fixture["evidence_attestations"][0].pop("stale")
    result = normalize(fixture)
    assert "RC.EVIDENCE.STALE" in codes(result)


def test_unavailable_evidence_cannot_be_promoted():
    fixture = load_fixture()
    fixture["evidence_attestations"][0]["verdict"] = "UNAVAILABLE"
    result = normalize(fixture)
    assert "RC.EVIDENCE.NON_PASS" in codes(result)


def test_unbound_evidence_blocks():
    fixture = load_fixture()
    fixture["evidence_attestations"][0]["subject"]["run_id"] = "RUN-WRONG"
    result = normalize(fixture)
    assert "RC.EVIDENCE.UNBOUND" in codes(result)


def test_missing_provenance_binding_blocks():
    fixture = load_fixture()
    fixture["evidence_attestations"][0].pop("material_digest")
    result = normalize(fixture)
    assert "RC.EVIDENCE.PROVENANCE_INCOMPLETE" in codes(result)
    assert "RC.EVIDENCE.DIGEST_INVALID" in codes(result)


def test_top_level_required_provenance_fields_are_enforced_when_profile_declares_them():
    fixture = load_fixture()
    fixture["provenance_fields"] = ["source_revision", "material_digest", "environment"]
    fixture["evidence_attestations"][0].pop("environment")
    result = normalize(fixture)
    assert "RC.EVIDENCE.PROVENANCE_INCOMPLETE" in codes(result)


def test_legacy_source_revision_equality_is_profile_scoped_and_enforced():
    fixture = load_fixture()
    fixture["evidence_attestations"][0]["source_revision"] = "deadbeef"
    result = normalize(fixture)
    assert "RC.EVIDENCE.SOURCE_REVISION_MISMATCH" in codes(result)
    assert "RC.GATE.PASS_WITH_BLOCKING_CONTRADICTION" in codes(result)


def test_legacy_v1_0_cannot_switch_to_independent_revision_policy():
    p = load_policy()
    p["revision_binding"] = "INDEPENDENT_ALLOWED"
    p["policy_digest"] = ident.policy_digest(p)
    result = normalize(load_fixture(), p)
    assert "RC.EVIDENCE.IDENTITY_INVALID" in codes(result)
    assert "RC.ORACLE.MISSING" in codes(result)


def test_duplicate_evidence_ids_block_unambiguous_binding():
    fixture = load_fixture()
    fixture["evidence_attestations"].append(copy.deepcopy(fixture["evidence_attestations"][0]))
    result = normalize(fixture)
    assert "RC.EVIDENCE.DUPLICATE_ID" in codes(result)


def test_required_oracle_must_have_current_passing_bound_identity_authorized_evidence():
    fixture = load_fixture()
    fixture["run_plan"]["required_oracles"] = ["dde-analytic-reference", "independent-oracle-B"]
    result = normalize(fixture)
    assert "RC.ORACLE.MISSING" in codes(result)


def test_forged_legacy_oracle_label_is_not_coverage():
    fixture = load_fixture()
    fixture["evidence_attestations"][0]["oracle_id"] = "forged-oracle"
    result = normalize(fixture)
    assert "RC.ORACLE.VERIFIER_MISMATCH" in codes(result)
    assert "RC.ORACLE.MISSING" in codes(result)


def test_missing_or_mutated_policy_fails_closed():
    missing = mod.normalize(load_fixture(), None)
    assert "RC.IDENTITY.POLICY_MISSING" in codes(missing)
    assert missing["blocking"] is True

    p = load_policy()
    p["legacy_verifier_versions"]["dde-analytic-reference"].append("forged-version")
    mutated = normalize(load_fixture(), p)
    assert "RC.IDENTITY.POLICY_INVALID" in codes(mutated)
    assert mutated["blocking"] is True


def test_v1_1_independent_evidence_revision_is_allowed_under_explicit_policy():
    fixture = convert_all_evidence_to_v1_1(load_fixture())
    result = normalize(fixture, independent_policy())
    assert result["blocking"] is False
    assert result["contradictions"] == []
    rec = next(r for r in result["records"] if r["record_type"] == "provenance.evidence_attestation")
    assert rec["identity"]["provenance"]["evidence_producer"]["revision"].startswith(
        "independent-evidence-rev"
    )


def test_v1_1_run_producer_revision_must_still_bind_run_plan():
    fixture = convert_all_evidence_to_v1_1(load_fixture())
    fixture["evidence_attestations"][0]["provenance"]["run_producer"]["revision"] = "wrong-run-rev"
    result = normalize(fixture, independent_policy())
    assert "RC.EVIDENCE.IDENTITY_INVALID" in codes(result)


def test_v1_1_forged_direct_oracle_label_fails():
    fixture = convert_all_evidence_to_v1_1(load_fixture())
    fixture["evidence_attestations"][0]["oracle_binding"]["oracle_id"] = "forged-oracle"
    result = normalize(fixture, independent_policy())
    assert "RC.ORACLE.VERIFIER_MISMATCH" in codes(result)
    assert "RC.ORACLE.MISSING" in codes(result)


def test_v1_1_missing_verifier_implementation_revision_fails():
    fixture = convert_all_evidence_to_v1_1(load_fixture())
    del fixture["evidence_attestations"][0]["verifier"]["implementation"]["revision"]
    result = normalize(fixture, independent_policy())
    assert "RC.EVIDENCE.IDENTITY_INVALID" in codes(result)


def test_v1_1_policy_alias_requires_authorization_tuple_and_bound_policy_ref():
    fixture = convert_all_evidence_to_v1_1(load_fixture())
    p = independent_policy()
    p["oracle_authorizations"] = [
        {
            "oracle_id": "dde-analytic-reference",
            "verifier_id": "external-oracle-harness",
            "verifier_implementation_id": "approved-oracle-impl",
        }
    ]
    p["policy_digest"] = ident.policy_digest(p)
    for item in fixture["evidence_attestations"]:
        item["verifier"]["id"] = "external-oracle-harness"
        item["verifier"]["implementation"]["id"] = "approved-oracle-impl"
        item["oracle_binding"] = {
            "oracle_id": "dde-analytic-reference",
            "mode": "POLICY",
            "policy_ref": {
                "policy_id": p["policy_id"],
                "policy_version": p["policy_version"],
                "policy_digest": p["policy_digest"],
            },
        }
    assert normalize(fixture, p)["blocking"] is False

    fixture["evidence_attestations"][0]["verifier"]["implementation"]["id"] = "forged-impl"
    rejected = normalize(fixture, p)
    assert "RC.ORACLE.POLICY_REJECTED" in codes(rejected)


def test_pass_gate_must_bind_claim_and_have_valid_digest():
    fixture = load_fixture()
    fixture["gate_reports"][0]["subject_id"] = "CLM-WRONG"
    fixture["gate_reports"][0]["input_digest"] = "not-a-digest"
    result = normalize(fixture)
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
    result = normalize(fixture)
    assert "RC.SUPERSESSION.FAIL" in codes(result)
    assert "RC.SUPERSESSION.STALE_DEPENDENCY" in codes(result)


def test_record_order_is_normalized_even_when_input_evidence_order_changes():
    fixture = load_fixture()
    a = normalize(fixture)
    fixture["evidence_attestations"].reverse()
    b = normalize(fixture)
    assert a["records"] == b["records"]
    # Input digest intentionally binds exact input JSON including array order.
    assert a["input_digest"] != b["input_digest"]
    assert a["output_digest"] != b["output_digest"]
