# Research Contract -> ARK normalization candidate

This integration layer maps shared Research Contract evidence into deterministic ARK-style provenance/event/contradiction records without modifying the frozen ARK-Core v1.0.5 decision surface.

## Guarantees in this candidate

- exact JSON input is bound by a SHA-256 `input_digest`;
- ClaimCard and RunPlan content are independently bound inside `contract_bindings`;
- source evidence objects are preserved losslessly, including verifier/oracle/provenance identities;
- promoted evidence fails closed when stale/freshness is absent, non-PASS, dangling, duplicate, unbound, provenance-incomplete, digest-malformed, or rejected by the selected identity policy;
- **revision equality is no longer a generic invariant**: v1.0 equality exists only in the named producer-local DDE compatibility profile; v1.1 independent evidence may carry a different evidence-producer revision;
- required-oracle coverage counts only current, bound, digest-valid, **identity-authorized** positive evidence;
- a free-form legacy `oracle_id` cannot self-authorize coverage: the compatibility profile requires direct `oracle_id == verifier.id`;
- v1.1 oracle aliases require an out-of-band policy ID/version/content-digest match plus an authorization tuple;
- PASS gates require claim binding, canonical SHA-256 digest syntax and evaluator revision metadata;
- supersession FAIL/stale-dependency findings are blocking contradictions;
- output is deterministic for identical JSON input plus identical selected policy and emits a SHA-256 `output_digest`.

## Identity policy is a consumer input

The CLI now requires:

```text
--identity-policy integration/research_contract_v1/policies/<policy>.json
```

The policy is not accepted from the evidence bundle itself. This prevents an evidence producer from choosing a permissive oracle/revision policy and thereby authorizing its own claim.

The current real DDE fixture uses `dde_producer_local_legacy_v1.json`, a compatibility-only policy for `EvidenceAttestation v1.0.0`. Independent solver/measurement/human-review evidence must be regenerated into the v1.1 identity shape before generic promotion.

Policy bytes are content-bound: `policy_digest` is SHA-256 over deterministic JSON with the `policy_digest` member omitted. Any policy mutation without an explicit repin fails closed.

## Deterministic encoding boundary

The exact JSON input includes array order. Record output is normalized by record type/source ID, but the `input_digest` intentionally changes if input array order changes. The project-local `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)` encoding is deterministic for the supported domain but is **not claimed to implement RFC 8785/JCS**.

## Trust boundary

`blocking=false` means the candidate ARK normalization rules found no configured audit/provenance contradiction. It does **not** prove scientific truth, general DDE correctness, numerical stability, bifurcation results, SLSA conformance, signer authenticity, or malicious-author independence.

A downstream receipt that merely repeats this candidate's revision and digests is not an independent trust anchor. Release-grade assurance requires independently protected expected identities plus actual cryptographic verification of any signed provenance/attestation and its trusted signer/root policy.

## Freeze and promotion boundary

`integration/research_contract_v1/` remains outside the ARK v1.0.5 freeze manifest while this work is a Draft PR. Therefore a v1.0.5 freeze PASS must not be interpreted as integrity coverage of this candidate adapter.

Before promotion choose one explicit path:

1. include implementation/spec/tests/policies in a new freeze-manifest release and re-freeze deliberately; or
2. keep the adapter as a separately versioned package with its own release integrity/provenance policy.

Do not silently extend the meaning of the v1.0.5 freeze.
