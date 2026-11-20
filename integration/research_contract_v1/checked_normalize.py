"""Require gate R2 *before* running Research Contract normalizer.

A reference integration seam, not a deployed normalizer. The injected normalizer
must already have been integrity-verified and selected from a trustworthy source.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from trusted_gate_pin_r2 import verify_bundle_r2, R2Error
from trusted_gate_pin import digest as project_digest
import hmac
import re


def checked_normalize(
    bundle: dict[str, Any],
    consumer_pin: dict[str, Any],
    identity_policy: dict[str, Any],
    normalizer: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]],
    expected_identity_policy_digest: str,
) -> dict[str, Any]:
    """Fail before running untrusted/side-effecting normalization on failed preflight.

    Crucially, identity_policy must also be selected/pinned OUT OF BAND; this API
    cannot authenticate its origin. A successful result is a bounded audit pass,
    not scientific validity or a release authorization.
    """
    preflight = verify_bundle_r2(bundle, consumer_pin)
    if not isinstance(identity_policy, dict):
        raise R2Error("normalize:identity-policy-not-object")
    if not isinstance(expected_identity_policy_digest, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", expected_identity_policy_digest) is None:
        raise R2Error("normalize:expected-identity-policy-digest-invalid")
    try:
        actual_policy_digest = project_digest(identity_policy)
    except (TypeError, ValueError, OverflowError, UnicodeError) as exc:
        raise R2Error("normalize:identity-policy-not-canonical") from exc
    if not hmac.compare_digest(actual_policy_digest, expected_identity_policy_digest):
        raise R2Error("normalize:identity-policy-not-pinned")
    result = normalizer(bundle, identity_policy)
    if not isinstance(result, dict):
        raise R2Error("normalize:invalid-output-type")
    if result.get("blocking") is not False or result.get("contradictions") != []:
        raise R2Error("normalize:blocked-or-unverified")
    contract_bindings = result.get("contract_bindings")
    if not isinstance(contract_bindings, dict):
        raise R2Error("normalize:missing-contract-bindings")
    ident = contract_bindings.get("evidence_identity_policy")
    if not isinstance(ident, dict) or ident.get("valid") is not True:
        raise R2Error("normalize:identity-policy-not-validated-by-normalizer")
    for field in ("policy_id", "policy_version", "policy_digest"):
        if ident.get(field) != identity_policy.get(field):
            raise R2Error("normalize:identity-policy-binding-mismatch")
    bindings = contract_bindings.get("gate_input_materialization")
    if not isinstance(bindings, list) or len(bindings) != 1:
        raise R2Error("normalize:gate-binding-count")
    b = bindings[0]
    if not isinstance(b, dict) or b.get("verified") is not True:
        raise R2Error("normalize:gate-unverified")
    if b.get("gate_id") != preflight["gate_id"] or b.get("input_digest") != preflight["input_digest"]:
        raise R2Error("normalize:gate-preflight-mismatch")
    output_digest = result.get("output_digest")
    if not isinstance(output_digest, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", output_digest) is None:
        raise R2Error("normalize:output-digest-invalid")
    normalized = {k:v for k,v in result.items() if k != "output_digest"}
    try:
        recomputed = project_digest(normalized)
    except (TypeError, ValueError, OverflowError, UnicodeError) as exc:
        raise R2Error("normalize:output-not-canonical") from exc
    if not hmac.compare_digest(recomputed, output_digest):
        raise R2Error("normalize:output-digest-mismatch")
    return {
        "status": "AUDIT_CONTRACT_CHECKS_PASSED",
        "preflight": preflight,
        "normalized_output_digest": result.get("output_digest"),
        "identity_policy_digest": actual_policy_digest,
        "scientific_truth": "NOT_ESTABLISHED",
        "release_trust": "NOT_ESTABLISHED",
    }
