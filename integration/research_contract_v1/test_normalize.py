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


def to_v1_1(fixture):
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
                "revision": f"independent-evidence-rev-{index}",
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
    assert result["schema_version"] == "1.2.0-candidate"
    assert result["contract_bindings"]["evidence_identity_policy"]["policy_id"] == (
        "DDE-PRODUCER-LOCAL-LEGACY-v1"
    )
    assert result["contract_bindings"]["evidence_identity_policy"]["valid"] is True


def test_output_is_stable_and_binds_run_content():
    fixture = load_fixture()
    policy = load_policy()
    a = normalize(fixture, policy)
    b = normalize(copy.deepcopy(fixture), copy.deepcopy(policy))
    assert a == b
    changed = copy.deepcopy(fixture)
    changed["run_plan"]["tolerances"]["atol"] = 0.0006
    c = normalize(changed, policy)
    assert c["input_digest"] != a["input_digest"]
    assert c["contract_bindings"]["run_plan_digest"] != a["contract_bindings"]["run_plan_digest"]


def test_source_object_and_identity_are_preserved_losslessly():
    fixture = load_fixture()
    result = normalize(fixture)
    source = fixture["evidence_attestations"][0]
    rec = next(r for r in result["records"] if r["source_id"] == source["evidence_id"])
    assert rec["source_revision"] == source["source_revision"]
    assert rec["material_digest"] == source["material_digest"]
    assert rec["identity"]["verifier"] == source["verifier"]
    assert rec["identity"]["legacy_oracle_id"] == source["oracle_id"]
    assert rec["source_object"] == source


def test_stale_unavailable_unbound_and_missing_digest_fail_closed():
    stale = load_fixture()
    stale["evidence_attestations"][0]["stale"] = True
    assert "RC.EVIDENCE.STALE" in codes(normalize(stale))

    unavailable = load_fixture()
    unavailable["evidence_attestations"][0]["verdict"] = "UNAVAILABLE"
    assert "RC.EVIDENCE.NON_PASS" in codes(normalize(unavailable))

    unbound = load_fixture()
    unbound["evidence_attestations"][0]["subject"]["run_id"] = "RUN-WRONG"
    assert "RC.EVIDENCE.UNBOUND" in codes(normalize(unbound))

    missing = load_fixture()
    missing["evidence_attestations"][0].pop("material_digest")
    result = normalize(missing)
    assert {"RC.EVIDENCE.PROVENANCE_INCOMPLETE", "RC.EVIDENCE.DIGEST_INVALID"} <= codes(result)


def test_legacy_revision_equality_is_only_profile_scoped():
    fixture = load_fixture()
    fixture["evidence_attestations"][0]["source_revision"] = "deadbeef"
    assert "RC.EVIDENCE.SOURCE_REVISION_MISMATCH" in codes(normalize(fixture))

    p = load_policy()
    p["revision_binding"] = "INDEPENDENT_ALLOWED"
    p["policy_digest"] = ident.policy_digest(p)
    result = normalize(load_fixture(), p)
    assert "RC.EVIDENCE.IDENTITY_INVALID" in codes(result)
    assert "RC.ORACLE.MISSING" in codes(result)


def test_duplicate_ids_and_missing_required_oracle_block():
    fixture = load_fixture()
    fixture["evidence_attestations"].append(copy.deepcopy(fixture["evidence_attestations"][0]))
    assert "RC.EVIDENCE.DUPLICATE_ID" in codes(normalize(fixture))

    fixture = load_fixture()
    fixture["run_plan"]["required_oracles"].append("independent-oracle-B")
    assert "RC.ORACLE.MISSING" in codes(normalize(fixture))


def test_one_forged_oracle_does_not_erase_other_valid_coverage():
    fixture = load_fixture()
    fixture["evidence_attestations"][0]["oracle_id"] = "forged-oracle"
    result = normalize(fixture)
    assert "RC.ORACLE.VERIFIER_MISMATCH" in codes(result)
    # The second valid evidence item still covers dde-analytic-reference.
    assert "RC.ORACLE.MISSING" not in codes(result)


def test_all_forged_legacy_oracle_evidence_removes_coverage():
    fixture = load_fixture()
    for item in fixture["evidence_attestations"]:
        item["oracle_id"] = "forged-oracle"
    result = normalize(fixture)
    assert "RC.ORACLE.VERIFIER_MISMATCH" in codes(result)
    assert "RC.ORACLE.MISSING" in codes(result)


def test_missing_or_mutated_policy_fails_closed():
    missing = mod.normalize(load_fixture(), None)
    assert "RC.IDENTITY.POLICY_MISSING" in codes(missing)
    p = load_policy()
    p["legacy_verifier_versions"]["dde-analytic-reference"].append("forged-version")
    assert "RC.IDENTITY.POLICY_INVALID" in codes(normalize(load_fixture(), p))


def test_v1_1_independent_evidence_revision_is_allowed():
    fixture = to_v1_1(load_fixture())
    result = normalize(fixture, independent_policy())
    assert result["blocking"] is False
    assert result["contradictions"] == []


def test_v1_1_run_producer_still_binds_run_plan():
    fixture = to_v1_1(load_fixture())
    fixture["evidence_attestations"][0]["provenance"]["run_producer"]["revision"] = "wrong"
    assert "RC.EVIDENCE.IDENTITY_INVALID" in codes(normalize(fixture, independent_policy()))


def test_one_forged_v1_1_oracle_does_not_erase_other_valid_coverage():
    fixture = to_v1_1(load_fixture())
    fixture["evidence_attestations"][0]["oracle_binding"]["oracle_id"] = "forged-oracle"
    result = normalize(fixture, independent_policy())
    assert "RC.ORACLE.VERIFIER_MISMATCH" in codes(result)
    assert "RC.ORACLE.MISSING" not in codes(result)


def test_all_forged_v1_1_oracles_remove_coverage():
    fixture = to_v1_1(load_fixture())
    for item in fixture["evidence_attestations"]:
        item["oracle_binding"]["oracle_id"] = "forged-oracle"
    result = normalize(fixture, independent_policy())
    assert "RC.ORACLE.VERIFIER_MISMATCH" in codes(result)
    assert "RC.ORACLE.MISSING" in codes(result)


def test_v1_1_missing_verifier_revision_fails():
    fixture = to_v1_1(load_fixture())
    del fixture["evidence_attestations"][0]["verifier"]["implementation"]["revision"]
    assert "RC.EVIDENCE.IDENTITY_INVALID" in codes(normalize(fixture, independent_policy()))


def test_v1_1_policy_alias_requires_authorized_tuple():
    fixture = to_v1_1(load_fixture())
    p = independent_policy()
    p["oracle_authorizations"] = [{
        "oracle_id": "dde-analytic-reference",
        "verifier_id": "external-oracle-harness",
        "verifier_implementation_id": "approved-oracle-impl",
    }]
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
    assert "RC.ORACLE.POLICY_REJECTED" in codes(normalize(fixture, p))


def test_pass_gate_and_supersession_findings_remain_blocking():
    fixture = load_fixture()
    fixture["gate_reports"][0]["subject_id"] = "CLM-WRONG"
    fixture["gate_reports"][0]["input_digest"] = "bad"
    result = normalize(fixture)
    assert {"RC.GATE.UNBOUND", "RC.GATE.INPUT_DIGEST_INVALID"} <= codes(result)

    fixture = load_fixture()
    fixture["supersession_reports"] = [{
        "report_id": "SUPER-DDE-001",
        "type": "SupersessionReport",
        "result": "FAIL",
        "valid": False,
        "stale_dependencies": ["CLM-OLD-001"],
    }]
    result = normalize(fixture)
    assert {"RC.SUPERSESSION.FAIL", "RC.SUPERSESSION.STALE_DEPENDENCY"} <= codes(result)


def test_record_order_normalizes_while_input_digest_binds_array_order():
    fixture = load_fixture()
    a = normalize(fixture)
    fixture["evidence_attestations"].reverse()
    b = normalize(fixture)
    assert a["records"] == b["records"]
    assert a["input_digest"] != b["input_digest"]
    assert a["output_digest"] != b["output_digest"]
