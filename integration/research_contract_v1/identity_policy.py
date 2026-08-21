from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


@dataclass(frozen=True)
class IdentityEvaluation:
    ok: bool
    reasons: tuple[str, ...]
    authorized_oracle: str | None
    evidence_revision: str | None


def canonical_bytes(value: Any) -> bytes:
    """ARK project-local deterministic JSON; intentionally not RFC 8785/JCS."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def policy_digest(policy: Mapping[str, Any]) -> str:
    """Hash policy content without the self-referential policy_digest field."""
    payload = {k: v for k, v in policy.items() if k != "policy_digest"}
    return "sha256:" + hashlib.sha256(canonical_bytes(payload)).hexdigest()


def validate_policy(policy: Mapping[str, Any] | None) -> tuple[str, ...]:
    if policy is None:
        return ("identity-policy-missing",)
    reasons: list[str] = []
    if policy.get("schema_name") != "ARKEvidenceIdentityPolicy":
        reasons.append("identity-policy-schema-name-invalid")
    if policy.get("schema_version") != "1.0.0":
        reasons.append("identity-policy-schema-version-invalid")
    for key in ("policy_id", "policy_version", "policy_digest", "revision_binding", "legacy_mode"):
        if not isinstance(policy.get(key), str) or not policy.get(key):
            reasons.append(f"identity-policy-missing-{key}")
    declared = policy.get("policy_digest")
    if isinstance(declared, str):
        if not _SHA256_RE.fullmatch(declared):
            reasons.append("identity-policy-digest-format-invalid")
        else:
            try:
                expected = policy_digest(policy)
            except (TypeError, ValueError):
                reasons.append("identity-policy-noncanonical-json")
            else:
                if declared != expected:
                    reasons.append("identity-policy-content-digest-mismatch")
    if policy.get("revision_binding") not in {"EQUAL_EVIDENCE_TO_RUN", "INDEPENDENT_ALLOWED"}:
        reasons.append("identity-policy-revision-binding-invalid")
    if policy.get("legacy_mode") not in {"DISABLED", "DDE_PRODUCER_LOCAL_EXPLICIT"}:
        reasons.append("identity-policy-legacy-mode-invalid")
    return tuple(reasons)


def _str(obj: Mapping[str, Any] | None, key: str, reasons: list[str], prefix: str) -> str | None:
    if obj is None:
        reasons.append(f"{prefix}-not-object")
        return None
    value = obj.get(key)
    if not isinstance(value, str) or not value:
        reasons.append(f"{prefix}-missing-{key}")
        return None
    return value


def _mapping(value: Any) -> Mapping[str, Any] | None:
    return value if isinstance(value, Mapping) else None


def _alias_authorized(
    policy: Mapping[str, Any],
    *,
    oracle_id: str,
    verifier_id: str,
    implementation_id: str,
) -> bool:
    raw = policy.get("oracle_authorizations")
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        return False
    return any(
        isinstance(item, Mapping)
        and item.get("oracle_id") == oracle_id
        and item.get("verifier_id") == verifier_id
        and item.get("verifier_implementation_id") == implementation_id
        for item in raw
    )


def _legacy_verifier_version_allowed(
    policy: Mapping[str, Any], verifier_id: str, verifier_version: str
) -> bool:
    raw = policy.get("legacy_verifier_versions")
    if not isinstance(raw, Mapping):
        return False
    allowed = raw.get(verifier_id)
    if not isinstance(allowed, Sequence) or isinstance(allowed, (str, bytes)):
        return False
    return verifier_version in allowed


def evaluate_evidence_identity(
    evidence: Mapping[str, Any],
    run_plan: Mapping[str, Any],
    source: Mapping[str, Any],
    policy: Mapping[str, Any] | None,
) -> IdentityEvaluation:
    """Evaluate identity semantics without treating evidence as its own trust policy."""
    policy_reasons = list(validate_policy(policy))
    if policy is None:
        return IdentityEvaluation(False, tuple(policy_reasons), None, None)

    reasons = policy_reasons
    schema_version = evidence.get("schema_version")
    run_revision = run_plan.get("code_revision")
    if not isinstance(run_revision, str) or not run_revision:
        reasons.append("run-code-revision-missing")

    authorized_oracle: str | None = None
    evidence_revision: str | None = None

    if schema_version == "1.0.0":
        # v1.0 cannot generically distinguish run/evidence/verifier revisions.
        # It is accepted only through the explicit producer-local DDE profile.
        if policy.get("legacy_mode") != "DDE_PRODUCER_LOCAL_EXPLICIT":
            reasons.append("legacy-v1.0-identity-underspecified")
        expected_repo = policy.get("legacy_source_repository")
        actual_repo = source.get("producer_repository")
        if not isinstance(expected_repo, str) or not expected_repo:
            reasons.append("legacy-policy-source-repository-missing")
        elif actual_repo != expected_repo:
            reasons.append("legacy-source-repository-mismatch")
        if policy.get("revision_binding") != "EQUAL_EVIDENCE_TO_RUN":
            reasons.append("legacy-v1.0-requires-producer-local-equality")

        evidence_revision = evidence.get("source_revision") if isinstance(evidence.get("source_revision"), str) else None
        if not evidence_revision:
            reasons.append("legacy-source-revision-missing")
        elif isinstance(run_revision, str) and evidence_revision != run_revision:
            reasons.append("legacy-source-revision-mismatch")

        verifier = _mapping(evidence.get("verifier"))
        verifier_id = _str(verifier, "id", reasons, "legacy-verifier")
        verifier_version = _str(verifier, "version", reasons, "legacy-verifier")
        if verifier_id and verifier_version and not _legacy_verifier_version_allowed(
            policy, verifier_id, verifier_version
        ):
            reasons.append("legacy-verifier-version-not-authorized")

        oracle_id = evidence.get("oracle_id")
        if oracle_id is not None:
            if not isinstance(oracle_id, str) or not oracle_id:
                reasons.append("legacy-oracle-id-invalid")
            elif verifier_id is not None and oracle_id != verifier_id:
                # v1.0 has no implementation-id field; aliasing is therefore not
                # generic-safe. Require direct identity in this compatibility profile.
                reasons.append("legacy-oracle-verifier-mismatch")
            else:
                authorized_oracle = oracle_id

    elif schema_version == "1.1.0":
        provenance = _mapping(evidence.get("provenance"))
        run_producer = _mapping(provenance.get("run_producer")) if provenance else None
        evidence_producer = _mapping(provenance.get("evidence_producer")) if provenance else None
        _str(run_producer, "id", reasons, "run-producer")
        run_producer_revision = _str(run_producer, "revision", reasons, "run-producer")
        _str(evidence_producer, "id", reasons, "evidence-producer")
        evidence_revision = _str(evidence_producer, "revision", reasons, "evidence-producer")

        if (
            run_producer_revision is not None
            and isinstance(run_revision, str)
            and run_producer_revision != run_revision
        ):
            reasons.append("run-producer-revision-mismatch")
        if (
            policy.get("revision_binding") == "EQUAL_EVIDENCE_TO_RUN"
            and evidence_revision is not None
            and isinstance(run_revision, str)
            and evidence_revision != run_revision
        ):
            reasons.append("evidence-producer-revision-mismatch")

        verifier = _mapping(evidence.get("verifier"))
        verifier_id = _str(verifier, "id", reasons, "verifier")
        implementation = _mapping(verifier.get("implementation")) if verifier else None
        implementation_id = _str(implementation, "id", reasons, "verifier-implementation")
        _str(implementation, "version", reasons, "verifier-implementation")
        _str(implementation, "revision", reasons, "verifier-implementation")

        oracle = _mapping(evidence.get("oracle_binding"))
        if evidence.get("oracle_binding") is not None:
            oracle_id = _str(oracle, "oracle_id", reasons, "oracle-binding")
            mode = oracle.get("mode") if oracle else None
            if mode == "DIRECT":
                if oracle_id and verifier_id and oracle_id != verifier_id:
                    reasons.append("oracle-verifier-mismatch")
                elif oracle_id:
                    authorized_oracle = oracle_id
            elif mode == "POLICY":
                ref = _mapping(oracle.get("policy_ref")) if oracle else None
                ref_id = _str(ref, "policy_id", reasons, "oracle-policy-ref")
                ref_version = _str(ref, "policy_version", reasons, "oracle-policy-ref")
                ref_digest = _str(ref, "policy_digest", reasons, "oracle-policy-ref")
                if ref_id != policy.get("policy_id"):
                    reasons.append("oracle-policy-id-mismatch")
                if ref_version != policy.get("policy_version"):
                    reasons.append("oracle-policy-version-mismatch")
                if ref_digest != policy.get("policy_digest"):
                    reasons.append("oracle-policy-digest-mismatch")
                if (
                    oracle_id
                    and verifier_id
                    and implementation_id
                    and _alias_authorized(
                        policy,
                        oracle_id=oracle_id,
                        verifier_id=verifier_id,
                        implementation_id=implementation_id,
                    )
                ):
                    authorized_oracle = oracle_id
                elif oracle_id and verifier_id and implementation_id:
                    reasons.append("oracle-verifier-not-authorized")
            else:
                reasons.append("oracle-binding-mode-invalid")
    else:
        reasons.append("evidence-schema-version-unsupported")

    # Oracle coverage must not survive any identity-policy contradiction.
    if reasons:
        authorized_oracle = None
    return IdentityEvaluation(not reasons, tuple(reasons), authorized_oracle, evidence_revision)
