# Research Contract v1 -> ARK normalization candidate

This integration layer maps shared Research Contract v1 evidence into deterministic ARK-style provenance/event/contradiction records without modifying the frozen ARK-Core v1.0.5 decision surface.

## Guarantees in this candidate

- exact JSON input is bound by a SHA-256 `input_digest`;
- ClaimCard and RunPlan content are independently bound inside `contract_bindings`;
- original evidence IDs, source revisions and material digests are preserved;
- promoted evidence fails closed when stale/freshness is absent, non-PASS, dangling, duplicate, unbound, provenance-incomplete, revision-mismatched or digest-malformed;
- required-oracle coverage counts only current, bound, revision-matching, digest-valid positive evidence;
- PASS gates require claim binding, a canonical SHA-256 input digest and evaluator revision metadata;
- supersession FAIL/stale-dependency findings are blocking contradictions;
- output is deterministic for identical JSON input and emits a SHA-256 `output_digest`.

The exact JSON input includes array order. Record output is normalized by record type/source ID, but the `input_digest` intentionally changes if input array order changes. This is byte/JSON-envelope identity, not a claim of semantic canonicalization.

## Trust boundary

`blocking=false` means the candidate ARK normalization rules found no configured audit/provenance contradiction. It does **not** prove scientific truth, general DDE correctness, numerical stability, bifurcation results, SLSA conformance, or artifact authenticity beyond the provenance material actually verified upstream.

A downstream receipt that merely repeats this candidate's revision and digests is not an independent trust anchor. Consumers should pin expected revision/input/output identities outside the receipt and, for release-grade assurance, verify a cryptographically authenticated provenance/attestation or equivalent protected-review trust anchor.

## Freeze and promotion boundary

`integration/research_contract_v1/` intentionally remains outside the ARK v1.0.5 freeze manifest while this work is a Draft PR. Therefore the existing v1.0.5 freeze PASS must not be interpreted as integrity coverage of this candidate integration code. Before promotion into a frozen/released ARK decision surface, choose one explicit path:

1. add the integration implementation/spec/tests to a new freeze-manifest release and re-freeze deliberately; or
2. keep it as a separately versioned adapter package with its own release integrity/provenance policy.

Do not silently extend the meaning of the v1.0.5 freeze.
