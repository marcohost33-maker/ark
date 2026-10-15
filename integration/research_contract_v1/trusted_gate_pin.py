"""Candidate ARK Research Contract gate-input trust pin (strict pilot scope).

An untrusted evidence bundle must not supply the authoritative list of documents
covered by its own gate. This module verifies a consumer-held pin BEFORE the
Research Contract normalizer is permitted to rely on a GateReport.

IMPORTANT: A SHA-256 content pin does not authenticate the pin's origin. Pin
provisioning, protection, review and release attestation stay external gates.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from collections.abc import Mapping, Sequence
from typing import Any

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import gate_input  # noqa: E402

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
ID_FIELDS = {
    "ModelSpec": "model_id",
    "RunPlan": "run_id",
    "EvidenceAttestation": "evidence_id",
    "ClaimCard": "claim_id",
}
STRICT_PIN_FIELDS = {
    "schema_name", "schema_version", "gate_id", "claim_id", "run_id",
    "profile_id", "profile_version", "profile_digest", "input_manifest",
    "scope_policy",
}


class TrustedPinError(ValueError):
    pass


def canonical_bytes(value: Any) -> bytes:
    """Preserve the explicit ARK project-local codec (not RFC 8785/JCS)."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def _object(value: Any, what: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise TrustedPinError(f"{what}:not-object")
    return value


def _array(value: Any, what: str) -> Sequence[Any]:
    if not isinstance(value, (list, tuple)):
        raise TrustedPinError(f"{what}:not-array")
    return value


def _text(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise TrustedPinError(f"{what}:missing-or-invalid")
    return value


def _document_key(doc: Mapping[str, Any]) -> tuple[str, str]:
    kind = _text(doc.get("schema_name"), "document.schema_name")
    if kind not in ID_FIELDS:
        raise TrustedPinError(f"document:unsupported-kind:{kind}")
    return (kind, _text(doc.get(ID_FIELDS[kind]), f"document.{ID_FIELDS[kind]}"))


def _manifest_keys(items: Any, what: str) -> list[tuple[str, str]]:
    entries = _array(items, what)
    if not entries:
        raise TrustedPinError(f"{what}:empty")
    keys = []
    for entry in entries:
        obj = _object(entry, what + ".entry")
        if set(obj) != {"kind", "id"}:
            raise TrustedPinError(f"{what}:entry-fields")
        kind = _text(obj.get("kind"), f"{what}.kind")
        ident = _text(obj.get("id"), f"{what}.id")
        if kind not in ID_FIELDS:
            raise TrustedPinError(f"{what}:unsupported-kind:{kind}")
        keys.append((kind, ident))
    if len(set(keys)) != len(keys):
        raise TrustedPinError(f"{what}:duplicate")
    return keys


def verify_bundle(bundle: Mapping[str, Any], pin: Mapping[str, Any]) -> dict[str, Any]:
    """Verify one pinned v1.1 gate and exact document closure, fail closed.

    This candidate deliberately supports one v1.1 gate / one claim per bundle and
    ALL_BUNDLE_EVIDENCE; multi-gate and SymbolSpec require separately reviewed specs.
    """
    bundle = _object(bundle, "bundle")
    pin = _object(pin, "pin")
    if set(pin) != STRICT_PIN_FIELDS:
        raise TrustedPinError("pin:field-set-mismatch")
    if pin["schema_name"] != "ARKTrustedGatePin" or pin["schema_version"] != "1.0.0":
        raise TrustedPinError("pin:unsupported-schema")
    if pin["scope_policy"] != "ALL_BUNDLE_EVIDENCE":
        raise TrustedPinError("pin:unsupported-scope")
    for key in ("gate_id", "claim_id", "run_id", "profile_id", "profile_version"):
        _text(pin[key], "pin." + key)
    if not isinstance(pin["profile_digest"], str) or not SHA256_RE.fullmatch(pin["profile_digest"]):
        raise TrustedPinError("pin:invalid-profile-digest")
    expected_keys = _manifest_keys(pin["input_manifest"], "pin.input_manifest")
    if len(expected_keys) < 4:
        raise TrustedPinError("pin:insufficient-inputs")
    kind_counts = {kind: sum(key[0] == kind for key in expected_keys) for kind in ID_FIELDS}
    if kind_counts["ModelSpec"] != 1 or kind_counts["RunPlan"] != 1 or kind_counts["ClaimCard"] != 1 or kind_counts["EvidenceAttestation"] < 1:
        raise TrustedPinError("pin:invalid-document-classes")
    if ("RunPlan", pin["run_id"]) not in expected_keys or ("ClaimCard", pin["claim_id"]) not in expected_keys:
        raise TrustedPinError("pin:run-or-claim-not-bound")

    # Reject unsupported future model additions, rather than silently excluding them.
    if "symbol_specs" in bundle and bundle["symbol_specs"]:
        raise TrustedPinError("bundle:unsupported-symbol-specs")

    profile_items = _array(bundle.get("gate_input_profiles"), "bundle.gate_input_profiles")
    if len(profile_items) != 1:
        raise TrustedPinError("bundle:profile-count-not-one")
    profile = _object(profile_items[0], "bundle.profile")
    if profile.get("profile_id") != pin["profile_id"] or profile.get("profile_version") != pin["profile_version"]:
        raise TrustedPinError("bundle:profile-identity-mismatch")
    if digest(profile) != pin["profile_digest"]:
        raise TrustedPinError("bundle:profile-digest-mismatch")
    if _manifest_keys(profile.get("inputs"), "bundle.profile.inputs") != expected_keys:
        raise TrustedPinError("bundle:profile-inputs-mismatch")

    reports = _array(bundle.get("gate_reports"), "bundle.gate_reports")
    if len(reports) != 1:
        raise TrustedPinError("bundle:gate-count-not-one")
    report = _object(reports[0], "bundle.gate_report")
    if report.get("gate_id") != pin["gate_id"] or report.get("subject_id") != pin["claim_id"]:
        raise TrustedPinError("bundle:gate-identity-mismatch")
    if report.get("schema_version") != "1.1.0":
        raise TrustedPinError("bundle:gate-not-v1.1")

    docs: list[Mapping[str, Any]] = []
    for key in ("model_spec", "run_plan", "claim_card"):
        docs.append(_object(bundle.get(key), "bundle." + key))
    evs = _array(bundle.get("evidence_attestations"), "bundle.evidence_attestations")
    if not evs:
        raise TrustedPinError("bundle:missing-evidence")
    docs += [_object(e, "bundle.evidence_attestation") for e in evs]

    indexed: dict[tuple[str, str], Mapping[str, Any]] = {}
    for doc in docs:
        key = _document_key(doc)
        if key in indexed:
            raise TrustedPinError(f"bundle:duplicate-document:{key}")
        indexed[key] = doc
    if set(indexed) != set(expected_keys):
        raise TrustedPinError("bundle:document-closure-mismatch")

    # The caller-supplied pin controls the order; never trust input ordering from
    # the bundle. gate_input binds full documents, not just their identity fields.
    ordered = [indexed[key] for key in expected_keys]
    try:
        check = gate_input.verify_report(report, profile, ordered)
    except (gate_input.GateInputBindingError, TypeError, ValueError, KeyError) as exc:
        raise TrustedPinError(f"bundle:gate-input-binding-failed:{exc}") from exc
    if _manifest_keys(check["input_manifest"], "verified.input_manifest") != expected_keys:
        raise TrustedPinError("bundle:verified-inputs-mismatch")
    return {
        "status": "BOUND_TO_CONSUMER_PIN",
        "gate_id": pin["gate_id"],
        "claim_id": pin["claim_id"],
        "run_id": pin["run_id"],
        "profile_digest": pin["profile_digest"],
        "input_digest": check["input_digest"],
        "input_count": len(expected_keys),
        "independent_release_trust": "NOT_VERIFIED",
        "scientific_truth": "NOT_ESTABLISHED",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Strict consumer-held GateProfile preflight; not a release verifier.")
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--trusted-pin", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    result: dict[str, Any]
    rc = 0
    try:
        bundle = json.loads(args.bundle.read_text(encoding="utf-8"))
        pin = json.loads(args.trusted_pin.read_text(encoding="utf-8"))
        result = verify_bundle(bundle, pin)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError, OverflowError, RecursionError) as exc:
        rc = 2
        result = {"status": "REJECT", "reason": str(exc)}
    try:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        # Always replace the previous verdict, including a failure, so stale PASS
        # cannot survive an input/policy failure. os.replace is atomic per FS.
        fd, tmp = tempfile.mkstemp(prefix=".ark-pin-", dir=args.out.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(result, handle, indent=2, sort_keys=True, ensure_ascii=False)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, args.out)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
    except OSError as exc:
        print(f"ERROR: cannot replace report: {exc}", file=sys.stderr)
        return 3
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
