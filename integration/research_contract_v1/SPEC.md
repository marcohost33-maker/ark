# ARK Research Contract Normalization — candidate v1

Status: candidate integration overlay; not part of the ARK-Core v1.0.5 freeze surface.

## Purpose

Normalize Research Contract v1 `EvidenceAttestation`, `GateReport`, and optional `SupersessionReport` objects into deterministic ARK audit/provenance records without changing the source objects or laundering audit success into scientific truth.

## Invariants

1. Source IDs, revisions and digests are copied verbatim into normalized records.
2. Input objects remain embedded under `source_object`; normalization never overwrites them.
3. Canonical output ordering is deterministic (record type, primary ID; contradictions by code and subject).
4. `output_digest` is SHA-256 over canonical UTF-8 JSON of the normalized payload excluding `output_digest` itself.
5. Promoted claim evidence (`ClaimCard.status` in PROVEN/BENCHMARKED/SUPPORTED/PASS/VERIFIED) is blocking-invalid when referenced evidence is missing, non-PASS/VERIFIED, stale, bound to another claim/run, lacks a material digest/source revision, or does not cover a required oracle from `RunPlan`.
6. A PASS `GateReport` is blocking-invalid when the promoted claim has any blocking evidence contradiction.
7. A `SupersessionReport` with `result=FAIL`, `valid=false`, or non-empty stale dependencies produces a blocking contradiction.
8. `UNAVAILABLE`, `UNVERIFIED`, `INDETERMINATE`, `ERROR`, and `FAIL` are never promoted to PASS.
9. ARK normalization/audit PASS means only that this normalization policy found no blocking contradiction. It is not scientific validation.

## Normalized record classes

- `provenance.evidence_attestation`
- `event.gate_report`
- `event.supersession_report`
- `contradiction`

## Exit codes

- `0`: normalization completed with no blocking contradictions.
- `2`: normalization completed and one or more blocking contradictions were emitted.
- `66`: invalid/missing input.
