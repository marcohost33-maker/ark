from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any

_ID_FIELD = {
    "ModelSpec": "model_id",
    "RunPlan": "run_id",
    "EvidenceAttestation": "evidence_id",
    "ClaimCard": "claim_id",
}


class GateInputBindingError(ValueError):
    pass


def _canon(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canon(value)).hexdigest()


def _document_key(document: Mapping[str, Any]) -> tuple[str, str]:
    kind = document.get("schema_name")
    if kind not in _ID_FIELD:
        raise GateInputBindingError(f"unsupported-kind:{kind!r}")
    field = _ID_FIELD[str(kind)]
    doc_id = document.get(field)
    if not isinstance(doc_id, str) or not doc_id:
        raise GateInputBindingError(f"missing-id:{kind}:{field}")
    return str(kind), doc_id


def materialize(profile: Mapping[str, Any], documents: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    expected_top = {
        "schema_name",
        "schema_version",
        "profile_id",
        "profile_version",
        "serialization",
        "digest_algorithm",
        "projection_policy",
        "ordering",
        "inputs",
    }
    if set(profile) != expected_top:
        raise GateInputBindingError("profile-fields-mismatch")
    constants = {
        "schema_name": "GateInputMaterializationProfile",
        "schema_version": "1.0.0",
        "serialization": "coworker-json-sortkeys-v1",
        "digest_algorithm": "sha256",
        "projection_policy": "FULL_DOCUMENT",
        "ordering": "PROFILE_DECLARED_INPUT_ORDER",
    }
    for key, value in constants.items():
        if profile.get(key) != value:
            raise GateInputBindingError(f"profile-{key}-unsupported")

    inputs = profile.get("inputs")
    if not isinstance(inputs, Sequence) or isinstance(inputs, (str, bytes)) or not inputs:
        raise GateInputBindingError("profile-inputs-invalid")

    declared: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for item in inputs:
        if not isinstance(item, Mapping) or set(item) != {"kind", "id"}:
            raise GateInputBindingError("profile-input-entry-invalid")
        key = (str(item["kind"]), str(item["id"]))
        if key in seen:
            raise GateInputBindingError(f"profile-duplicate-input:{key}")
        if key[0] not in _ID_FIELD or not key[1]:
            raise GateInputBindingError(f"profile-input-unsupported:{key}")
        seen.add(key)
        declared.append(key)

    index: dict[tuple[str, str], Mapping[str, Any]] = {}
    for document in documents:
        key = _document_key(document)
        if key in index:
            raise GateInputBindingError(f"documents-duplicate:{key}")
        index[key] = document

    if set(index) != set(declared):
        missing = sorted(set(declared) - set(index))
        extra = sorted(set(index) - set(declared))
        raise GateInputBindingError(f"documents-set-mismatch:missing={missing}:extra={extra}")

    manifest = [{"kind": kind, "id": doc_id} for kind, doc_id in declared]
    return {
        "schema_name": "GateInputMaterialization",
        "schema_version": "1.0.0",
        "profile": {
            "profile_id": profile["profile_id"],
            "profile_version": profile["profile_version"],
            "serialization": "coworker-json-sortkeys-v1",
            "digest_algorithm": "sha256",
            "projection_policy": "FULL_DOCUMENT",
            "ordering": "PROFILE_DECLARED_INPUT_ORDER",
        },
        "input_manifest": manifest,
        "documents": [
            {"kind": kind, "id": doc_id, "payload": index[(kind, doc_id)]}
            for kind, doc_id in declared
        ],
    }


def binding(profile: Mapping[str, Any], documents: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    value = materialize(profile, documents)
    return {
        "input_materialization_profile": {
            "profile_id": profile["profile_id"],
            "profile_version": profile["profile_version"],
        },
        "input_manifest": value["input_manifest"],
        "input_digest": _digest(value),
    }


def verify_report(
    report: Mapping[str, Any],
    profile: Mapping[str, Any],
    documents: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    if report.get("schema_version") != "1.1.0":
        raise GateInputBindingError(f"unsupported-gate-version:{report.get('schema_version')}")
    expected = binding(profile, documents)
    for key in ("input_materialization_profile", "input_manifest", "input_digest"):
        if report.get(key) != expected[key]:
            raise GateInputBindingError(f"gate-{key}-mismatch")
    return expected
