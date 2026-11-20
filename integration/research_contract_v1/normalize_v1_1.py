from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
import hashlib
import hmac
import json
from pathlib import Path
import sys
from typing import Any

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import gate_input  # noqa: E402
import normalize as core  # noqa: E402
import trusted_gate_pin_r2 as pin_gate  # noqa: E402
from trusted_gate_pin import TrustedPinError  # noqa: E402

EX_NOINPUT = 66


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


def _contradiction(code: str, subject: str, detail: str, source_ids: list[str]) -> dict[str, Any]:
    return {
        "record_type": "contradiction",
        "code": code,
        "severity": "HARD_FAIL",
        "blocking": True,
        "subject_id": subject,
        "detail": detail,
        "source_ids": sorted(set(source_ids)),
    }


def _profile_for_report(bundle: Mapping[str, Any], report: Mapping[str, Any]) -> Mapping[str, Any]:
    ref = report.get("input_materialization_profile")
    if not isinstance(ref, Mapping):
        raise gate_input.GateInputBindingError("gate-profile-reference-missing")
    profile_id = ref.get("profile_id")
    profile_version = ref.get("profile_version")
    profiles = bundle.get("gate_input_profiles")
    if not isinstance(profiles, Sequence) or isinstance(profiles, (str, bytes)):
        raise gate_input.GateInputBindingError("bundle-gate-input-profiles-missing")
    matches = [
        item
        for item in profiles
        if isinstance(item, Mapping)
        and item.get("profile_id") == profile_id
        and item.get("profile_version") == profile_version
    ]
    if len(matches) != 1:
        raise gate_input.GateInputBindingError(
            f"gate-profile-resolution-count:{len(matches)}:{profile_id}:{profile_version}"
        )
    return matches[0]


def _all_contract_documents(bundle: Mapping[str, Any]) -> dict[tuple[str, str], Mapping[str, Any]]:
    candidates: list[Mapping[str, Any]] = []
    for key in ("model_spec", "run_plan", "claim_card"):
        value = bundle.get(key)
        if isinstance(value, Mapping):
            candidates.append(value)
    for key in ("symbol_specs", "evidence_attestations"):
        value = bundle.get(key)
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
            candidates.extend(item for item in value if isinstance(item, Mapping))

    result: dict[tuple[str, str], Mapping[str, Any]] = {}
    for document in candidates:
        key = gate_input._document_key(document)
        if key in result:
            raise gate_input.GateInputBindingError(f"bundle-document-duplicate:{key}")
        result[key] = document
    return result


def _documents_for_profile(
    bundle: Mapping[str, Any], profile: Mapping[str, Any]
) -> list[Mapping[str, Any]]:
    index = _all_contract_documents(bundle)
    inputs = profile.get("inputs")
    if not isinstance(inputs, Sequence) or isinstance(inputs, (str, bytes)):
        raise gate_input.GateInputBindingError("profile-inputs-invalid")
    selected: list[Mapping[str, Any]] = []
    for item in inputs:
        if not isinstance(item, Mapping):
            raise gate_input.GateInputBindingError("profile-input-invalid")
        key = (str(item.get("kind")), str(item.get("id")))
        document = index.get(key)
        if document is None:
            raise gate_input.GateInputBindingError(f"bundle-document-missing:{key}")
        selected.append(document)
    return selected


def normalize(
    bundle: dict[str, Any],
    identity_policy: Mapping[str, Any] | None,
    trusted_pin: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Normalize v1.1 behind a mandatory consumer-held gate pin (ARK-F-001).

    The producer bundle cannot vouch for its own gate profile: a coordinated edit of
    profile, manifest and digest is internally consistent. The consumer pin fixes
    profile digest, input digest and GateReport digest out of band. Any pin failure
    raises TrustedPinError before the normalizer runs (fail closed).
    """
    if trusted_pin is None:
        raise TrustedPinError("pin:required")
    preflight = pin_gate.verify_bundle_r2(bundle, trusted_pin)
    result = _normalize_unpinned(bundle, identity_policy)
    result["contract_bindings"]["trusted_gate_pin"] = {
        key: preflight[key]
        for key in ("status", "gate_id", "profile_digest", "input_digest", "gate_report_digest")
    }
    result.pop("output_digest", None)
    result["output_digest"] = _digest(result)
    return result


def _normalize_unpinned(
    bundle: dict[str, Any], identity_policy: Mapping[str, Any] | None
) -> dict[str, Any]:
    """Bundle-internal v1.1 checks; NOT a trust decision without the pin preflight."""
    result = core.normalize(bundle, identity_policy)
    result["schema_version"] = "1.3.0-candidate"

    evidence = [
        item
        for item in bundle.get("evidence_attestations", [])
        if isinstance(item, Mapping)
    ]
    modern = any(item.get("schema_version") == "1.1.0" for item in evidence)
    gates = [item for item in bundle.get("gate_reports", []) if isinstance(item, Mapping)]
    v1_1_gates = [item for item in gates if item.get("schema_version") == "1.1.0"]

    bindings: list[dict[str, Any]] = []
    added: list[dict[str, Any]] = []
    claim_id = str((bundle.get("claim_card") or {}).get("claim_id", "<missing-claim>"))

    if modern and not v1_1_gates:
        added.append(
            _contradiction(
                "RC.GATE.V1_1_MISSING",
                claim_id,
                "v1.1 evidence requires at least one GateReport v1.1 with reconstructible input binding.",
                [claim_id],
            )
        )

    for report in v1_1_gates:
        gate_id = str(report.get("gate_id", "<missing-gate>"))
        try:
            profile = _profile_for_report(bundle, report)
            documents = _documents_for_profile(bundle, profile)
            verified = gate_input.verify_report(report, profile, documents)
        except (gate_input.GateInputBindingError, TypeError, ValueError) as exc:
            bindings.append({"gate_id": gate_id, "verified": False, "error": str(exc)})
            added.append(
                _contradiction(
                    "RC.GATE.INPUT_BINDING_INVALID",
                    gate_id,
                    f"GateReport v1.1 input binding cannot be reconstructed exactly: {exc}",
                    [gate_id, claim_id],
                )
            )
        else:
            bindings.append(
                {
                    "gate_id": gate_id,
                    "verified": True,
                    "profile_id": verified["input_materialization_profile"]["profile_id"],
                    "profile_version": verified["input_materialization_profile"]["profile_version"],
                    "input_digest": verified["input_digest"],
                    "input_count": len(verified["input_manifest"]),
                }
            )

    result.setdefault("contract_bindings", {})["gate_input_materialization"] = bindings
    result["contradictions"].extend(added)
    result["contradictions"].sort(
        key=lambda item: (item["code"], item["subject_id"], item["detail"])
    )
    result["blocking"] = any(item.get("blocking") for item in result["contradictions"])
    result.pop("output_digest", None)
    result["output_digest"] = _digest(result)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Normalize Research Contract v1.1 with exact GateReport input reconstruction."
    )
    parser.add_argument("input", type=Path)
    parser.add_argument("--identity-policy", type=Path, required=True)
    parser.add_argument("--trusted-pin", type=Path, required=True)
    parser.add_argument(
        "--expected-pin-sha256",
        required=True,
        help="sha256:<64 lowercase hex> over the EXACT trusted-pin file bytes, from independent configuration",
    )
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        bundle = json.loads(args.input.read_text(encoding="utf-8"))
        policy = json.loads(args.identity_policy.read_text(encoding="utf-8"))
        pin_bytes = pin_gate._read_bounded(args.trusted_pin, pin_gate.MAX_PIN_BYTES)
    except (OSError, json.JSONDecodeError, pin_gate.R2Error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EX_NOINPUT
    if not isinstance(bundle, dict) or not isinstance(policy, dict):
        print("error: input and identity policy must be JSON objects", file=sys.stderr)
        return EX_NOINPUT
    args.out.parent.mkdir(parents=True, exist_ok=True)
    try:
        if not pin_gate.SHA_RE.fullmatch(args.expected_pin_sha256):
            raise pin_gate.R2Error("pin:expected-pin-sha256-invalid")
        if not hmac.compare_digest(pin_gate.sha256_bytes(pin_bytes), args.expected_pin_sha256):
            raise pin_gate.R2Error("pin:out-of-band-file-digest-mismatch")
        pin = pin_gate.strict_json(pin_bytes, max_bytes=pin_gate.MAX_PIN_BYTES)
        result = normalize(bundle, policy, trusted_pin=pin)
    except TrustedPinError as exc:
        # Replace any earlier accepting output so a stale PASS cannot survive.
        reject = {"status": "REJECT", "reason": str(exc), "blocking": True}
        args.out.write_text(json.dumps(reject, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps(reject, sort_keys=True), file=sys.stderr)
        return 2
    args.out.write_text(
        json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "output_digest": result["output_digest"],
                "input_digest": result["input_digest"],
                "blocking": result["blocking"],
                "contradictions": len(result["contradictions"]),
                "gate_bindings": result["contract_bindings"]["gate_input_materialization"],
            },
            sort_keys=True,
        )
    )
    return 2 if result["blocking"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
