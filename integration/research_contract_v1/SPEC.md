# ARK Research Contract Normalization — candidate v1.2

Status: candidate integration overlay; not part of the ARK-Core v1.0.5 freeze surface.

## Purpose

Normalize Research Contract evidence into deterministic ARK audit/provenance records without changing source objects or laundering audit success into scientific truth.

## Core invariants

1. Source IDs, digests and all source identity fields are preserved losslessly under `source_object`; selected identity fields are also surfaced in a normalized `identity` summary.
2. Canonical output ordering is deterministic. The project-local JSON encoding is **not** claimed as RFC 8785/JCS.
3. `output_digest` is SHA-256 over the normalized payload before `output_digest` is added.
4. Promoted evidence must be referenced, PASS/VERIFIED, explicitly fresh, claim/run-bound, digest-bound and accepted by an **externally selected evidence identity policy**.
5. Required-oracle coverage counts only identity-authorized evidence; a free-form `oracle_id` is never sufficient by itself.
6. A PASS GateReport is blocking-invalid when the promoted claim has any blocking evidence contradiction.
7. Failing/stale SupersessionReports remain blocking.
8. `UNAVAILABLE`, `UNVERIFIED`, `INDETERMINATE`, `ERROR`, and `FAIL` are never promoted.
9. ARK normalization PASS is audit/provenance evidence only, not scientific truth.

## Evidence identity policy

The CLI requires `--identity-policy <path>`. The policy is supplied out-of-band from the evidence bundle so evidence cannot self-authorize its own revision/oracle semantics.

The current DDE v1.0 compatibility policy is:

`policies/dde_producer_local_legacy_v1.json`

It is intentionally narrow:

- `legacy_mode = DDE_PRODUCER_LOCAL_EXPLICIT`;
- source repository must be the declared DDE producer;
- `source_revision == RunPlan.code_revision` is required **only in this compatibility profile**;
- legacy verifier ID/version must be allowlisted by the policy;
- legacy oracle coverage requires direct `oracle_id == verifier.id`;
- switching legacy v1.0 to `INDEPENDENT_ALLOWED` fails closed.

The policy is content-bound. `policy_digest` is SHA-256 over deterministic JSON of the policy with the `policy_digest` member omitted, preventing a self-referential hash definition and detecting post-approval mutation.

## EvidenceAttestation v1.1

ARK also accepts the new explicit identity shape when a matching trusted policy is selected:

- `provenance.run_producer.{id,revision}` must bind the RunPlan producer revision;
- `provenance.evidence_producer.{id,revision}` may differ under `INDEPENDENT_ALLOWED`;
- `verifier.id` is separate from `verifier.implementation.{id,version,revision}`;
- `oracle_binding.mode = DIRECT` requires `oracle_id == verifier.id`;
- `oracle_binding.mode = POLICY` requires a matching policy ID/version/digest and an authorization tuple `(oracle_id, verifier_id, verifier_implementation_id)`.

This supports genuinely independent solver, measurement, formal-check and human-review evidence without falsely forcing all revisions to equal the run producer.

## Fail-closed migration boundary

Research Contract v1.0 does not contain enough fields to reconstruct generic independent-evidence identity. ARK therefore does **not** reinterpret a legacy v1.0 attestation as independent v1.1 evidence. Outside the explicitly selected DDE producer-local compatibility profile, v1.0 identity is blocking-unverified.

## Normalized record classes

- `provenance.evidence_attestation`
- `event.gate_report`
- `event.supersession_report`
- `contradiction`

## Exit codes

- `0`: normalization completed with no blocking contradictions.
- `2`: normalization completed and one or more blocking contradictions were emitted.
- `66`: invalid/missing JSON input or identity-policy file.

## Trust / release boundary

The overlay remains outside the frozen ARK-Core v1.0.5 integrity surface. A green core freeze gate does not cover this adapter. Promotion requires an explicit adapter freeze/package integrity decision, regenerated DDE→ARK→USK fixtures, adversarial CI, independent review and authenticated release provenance.
