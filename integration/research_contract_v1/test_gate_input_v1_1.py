from __future__ import annotations

import copy
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import gate_input  # noqa: E402
import normalize_v1_1 as norm  # noqa: E402

FIXTURE = HERE / "fixtures" / "dde_v1_1_real.json"
POLICY = HERE / "policies" / "dde_v1_1_candidate.json"
HQST_MINIMAL_DIGEST = (
    "sha256:8744844a3f1b4323dabaca05e0072638de5b3dba87ad6b581203463672f06048"
)
DDE_SCALAR_GATE_DIGEST = (
    "sha256:994f8b45fcd249fd0dceecd7fd3a94c4323c8588cee5a5d0661c88c00c02b25c"
)


def load_fixture():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def load_policy():
    return json.loads(POLICY.read_text(encoding="utf-8"))


def codes(result):
    return {item["code"] for item in result["contradictions"]}


def test_hqst_minimal_cross_implementation_vector_is_reproduced():
    profile = {
        "schema_name": "GateInputMaterializationProfile",
        "schema_version": "1.0.0",
        "profile_id": "HQST.GATE-EVID-001.DDE-REFERENCE-001",
        "profile_version": "1.0.0",
        "serialization": "coworker-json-sortkeys-v1",
        "digest_algorithm": "sha256",
        "projection_policy": "FULL_DOCUMENT",
        "ordering": "PROFILE_DECLARED_INPUT_ORDER",
        "inputs": [
            {"kind": "ModelSpec", "id": "dde.reference.linear"},
            {"kind": "RunPlan", "id": "RUN-DDE-001"},
            {"kind": "EvidenceAttestation", "id": "EVID-DDE-001"},
            {"kind": "ClaimCard", "id": "CLM-DDE-001"},
        ],
    }
    documents = [
        {
            "schema_name": "ModelSpec",
            "schema_version": "1.0.0",
            "model_id": "dde.reference.linear",
            "revision": "1.0.0",
        },
        {
            "schema_name": "RunPlan",
            "schema_version": "1.0.0",
            "run_id": "RUN-DDE-001",
            "model_id": "dde.reference.linear",
        },
        {
            "schema_name": "EvidenceAttestation",
            "schema_version": "1.0.0",
            "evidence_id": "EVID-DDE-001",
            "subject": {"claim_id": "CLM-DDE-001", "run_id": "RUN-DDE-001"},
        },
        {
            "schema_name": "ClaimCard",
            "schema_version": "1.0.0",
            "claim_id": "CLM-DDE-001",
            "status": "SUPPORTED",
        },
    ]
    assert gate_input.binding(profile, documents)["input_digest"] == HQST_MINIMAL_DIGEST


def test_real_dde_v1_1_fixture_normalizes_with_verified_gate_binding():
    result = norm.normalize(load_fixture(), load_policy())
    assert result["schema_version"] == "1.3.0-candidate"
    assert result["blocking"] is False
    assert result["contradictions"] == []
    policy_binding = result["contract_bindings"]["evidence_identity_policy"]
    assert policy_binding["policy_id"] == "DDE-EVIDENCE-IDENTITY-v1.1"
    assert policy_binding["valid"] is True
    bindings = result["contract_bindings"]["gate_input_materialization"]
    assert bindings == [
        {
            "gate_id": "GATE-DDE-PILOT-001",
            "verified": True,
            "profile_id": "DDE.GATE-EVID-001.scalar_linear_constant_delay",
            "profile_version": "1.0.0",
            "input_digest": DDE_SCALAR_GATE_DIGEST,
            "input_count": 7,
        }
    ]


def test_full_document_mutation_invalidates_gate_binding():
    fixture = load_fixture()
    fixture["model_spec"]["claim_ceiling"] = "mutated downstream after DDE gate"
    result = norm.normalize(fixture, load_policy())
    assert result["blocking"] is True
    assert "RC.GATE.INPUT_BINDING_INVALID" in codes(result)


def test_profile_order_mutation_invalidates_gate_binding():
    fixture = load_fixture()
    fixture["gate_input_profiles"][0]["inputs"] = list(
        reversed(fixture["gate_input_profiles"][0]["inputs"])
    )
    result = norm.normalize(fixture, load_policy())
    assert result["blocking"] is True
    assert "RC.GATE.INPUT_BINDING_INVALID" in codes(result)


def test_unreferenced_but_gate_bound_evidence_cannot_be_dropped():
    fixture = load_fixture()
    fixture["evidence_attestations"] = [
        item
        for item in fixture["evidence_attestations"]
        if "external_cross_solver_optional" not in item["evidence_id"]
    ]
    # The unavailable placeholder is not claim-positive evidence, but it is part of
    # the exact GateReport subject. Removing it must therefore invalidate the gate.
    result = norm.normalize(fixture, load_policy())
    assert result["blocking"] is True
    assert "RC.GATE.INPUT_BINDING_INVALID" in codes(result)


def test_policy_mutation_blocks_oracle_coverage_and_gate_promotion():
    policy = load_policy()
    policy["notes"].append("post-digest mutation")
    result = norm.normalize(load_fixture(), policy)
    assert result["blocking"] is True
    ids = codes(result)
    assert "RC.IDENTITY.POLICY_INVALID" in ids
    assert "RC.ORACLE.MISSING" in ids
    assert "RC.GATE.PASS_WITH_BLOCKING_CONTRADICTION" in ids


def test_v1_1_evidence_with_only_legacy_gate_fails_closed():
    fixture = load_fixture()
    gate = copy.deepcopy(fixture["gate_reports"][0])
    gate["schema_version"] = "1.0.0"
    gate.pop("input_materialization_profile")
    gate.pop("input_manifest")
    fixture["gate_reports"] = [gate]
    result = norm.normalize(fixture, load_policy())
    assert result["blocking"] is True
    assert "RC.GATE.V1_1_MISSING" in codes(result)
