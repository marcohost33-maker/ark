from __future__ import annotations

import copy
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import identity_policy as ident  # noqa: E402
import normalize as norm  # noqa: E402


def shared_policy():
    policy = {
        "schema_name": "EvidenceIdentityPolicy",
        "schema_version": "1.0.0",
        "policy_id": "DDE-EVIDENCE-IDENTITY-v1.1",
        "policy_version": "1.0.0",
        "policy_digest": "sha256:" + "0" * 64,
        "revision_binding": "INDEPENDENT_ALLOWED",
        "oracle_authorizations": [
            {
                "oracle_id": "dde-analytic-reference",
                "verifier_id": "stdlib_method_of_steps_rk4",
                "verifier_implementation_id": "coworker-dde.solver-vs-analytic-reference.stdlib_method_of_steps_rk4",
            }
        ],
        "legacy_mode": "DISABLED",
        "legacy_verifier_revisions": {},
        "notes": ["shared HQST/DDE v1.1 policy"],
    }
    policy["policy_digest"] = ident.policy_digest(policy)
    return policy


def bundle(policy):
    run_rev = "a" * 40
    evidence_rev = "b" * 40
    evidence = {
        "schema_name": "EvidenceAttestation",
        "schema_version": "1.1.0",
        "evidence_id": "EVID-DDE-shared-v1_1",
        "subject": {
            "artifact_id": "ART-DDE-shared-v1_1",
            "claim_id": "CLM-DDE-shared-v1_1",
            "run_id": "RUN-DDE-shared-v1_1",
        },
        "material_digest": "sha256:" + "c" * 64,
        "provenance": {
            "run_producer": {"id": "marcohost33-maker/coworker-dde", "revision": run_rev},
            "evidence_producer": {
                "id": "marcohost33-maker/coworker-dde:materialize-research-contracts-v1.1",
                "revision": evidence_rev,
            },
        },
        "verifier": {
            "id": "stdlib_method_of_steps_rk4",
            "kind": "independent-solver",
            "implementation": {
                "id": "coworker-dde.solver-vs-analytic-reference.stdlib_method_of_steps_rk4",
                "version": "0.1",
                "revision": run_rev,
            },
        },
        "oracle_binding": {
            "oracle_id": "dde-analytic-reference",
            "mode": "POLICY",
            "policy_ref": {
                "policy_id": policy["policy_id"],
                "policy_version": policy["policy_version"],
                "policy_digest": policy["policy_digest"],
            },
        },
        "method": "reference comparison",
        "verdict": "PASS",
        "stale": False,
        "timestamp": "2026-08-22T00:00:00Z",
        "environment": {"python": "3.12"},
        "limitations": ["reference case only"],
    }
    return {
        "source": {"producer_repository": "marcohost33-maker/coworker-dde"},
        "run_plan": {
            "schema_name": "RunPlan",
            "schema_version": "1.0.0",
            "run_id": "RUN-DDE-shared-v1_1",
            "model_id": "dde.shared",
            "code_revision": run_rev,
            "required_oracles": ["dde-analytic-reference"],
        },
        "claim_card": {
            "schema_name": "ClaimCard",
            "schema_version": "1.0.0",
            "claim_id": "CLM-DDE-shared-v1_1",
            "status": "SUPPORTED",
            "evidence_ids": [evidence["evidence_id"]],
        },
        "evidence_attestations": [evidence],
        "gate_reports": [],
        "supersession_reports": [],
    }


def codes(result):
    return {item["code"] for item in result["contradictions"]}


def test_shared_policy_accepts_v1_1_with_distinct_evidence_revision():
    policy = shared_policy()
    assert ident.validate_policy(policy) == ()
    result = norm.normalize(bundle(policy), policy)
    assert result["blocking"] is False
    assert result["contradictions"] == []
    binding = result["contract_bindings"]["evidence_identity_policy"]
    assert binding["policy_id"] == policy["policy_id"]
    assert binding["valid"] is True


def test_shared_policy_mutation_fails_content_binding():
    policy = shared_policy()
    mutated = copy.deepcopy(policy)
    mutated["notes"].append("mutation")
    result = norm.normalize(bundle(policy), mutated)
    assert result["blocking"] is True
    assert "RC.IDENTITY.POLICY_INVALID" in codes(result)


def test_shared_policy_cannot_enable_ark_legacy_mode():
    policy = shared_policy()
    policy["legacy_mode"] = "DDE_PRODUCER_LOCAL_EXPLICIT"
    policy["policy_digest"] = ident.policy_digest(policy)
    errors = ident.validate_policy(policy)
    assert "identity-policy-shared-schema-cannot-enable-ark-legacy-mode" in errors


def test_ark_legacy_policy_dialect_remains_separate():
    path = HERE / "policies" / "dde_producer_local_legacy_v1.json"
    policy = json.loads(path.read_text(encoding="utf-8"))
    assert policy["schema_name"] == "ARKEvidenceIdentityPolicy"
    assert ident.validate_policy(policy) == ()
