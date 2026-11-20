"""ARK Research Contract Consumer Gate Preflight R2 (candidate, NOT a release verifier).

Security properties, within explicit scope:
- immutable expected DOCUMENT PROFILE and INPUT DIGEST from a *separately* pinned policy;
- strict JSON parser (reject duplicate object keys, nonfinite literals, oversized JSON);
- fail closed on a failed GateReport; never equate proof of binding with scientific truth;
- CLI pins exact policy file bytes against a consumer-supplied out-of-band digest;
- atomic output replace, with preflight against overwriting input/pin paths.

LIMITS: trust in --expected-pin-sha256 itself, signing identities, repository release,
scientific claims and independent review are OUTSIDE this checker.

normalize_v1_1.normalize/main run verify_bundle_r2 as a mandatory preflight (ARK-F-001).
"""
from __future__ import annotations

import argparse
from collections.abc import Mapping
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import sys
import tempfile
from typing import Any

# Avoid adapting the upstream codec (the original digest must remain byte-identical).
from trusted_gate_pin import TrustedPinError, verify_bundle as verify_r1, digest as project_digest

SHA_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
MAX_BUNDLE_BYTES = 8 * 1024 * 1024
MAX_PIN_BYTES = 64 * 1024
MAX_TREE_DEPTH = 100
MAX_NODES = 100_000
MAX_GATE_DOCUMENTS = 1024


class R2Error(TrustedPinError):
    pass


def _duplicate_guard(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for k, value in pairs:
        if k in obj:
            raise R2Error(f"json:duplicate-member:{k}")
        obj[k] = value
    return obj


def _reject_constant(const: str) -> None:
    raise R2Error(f"json:nonfinite-literal:{const}")


def _check_tree(root: Any) -> None:
    # Iterative to avoid recursively trusting nested untrusted data.
    stack: list[tuple[Any, int]] = [(root, 0)]
    nodes = 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES:
            raise R2Error("json:node-limit")
        if depth > MAX_TREE_DEPTH:
            raise R2Error("json:depth-limit")
        if isinstance(value, dict):
            stack.extend((k, depth + 1) for k in value)
            stack.extend((v, depth + 1) for v in value.values())
        elif isinstance(value, list):
            stack.extend((v, depth + 1) for v in value)
        elif isinstance(value, float) and not math.isfinite(value):
            raise R2Error("json:nonfinite-number")
        elif isinstance(value, str):
            if any(0xD800 <= ord(c) <= 0xDFFF for c in value):
                raise R2Error("json:unpaired-surrogate")
        elif value is not None and not isinstance(value, (bool, int, float)):
            raise R2Error("json:unsupported-type")


def strict_json(raw: bytes, *, max_bytes: int) -> Any:
    if len(raw) > max_bytes:
        raise R2Error("json:byte-limit")
    try:
        data = raw.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise R2Error("json:not-utf8") from exc
    if data.startswith("\ufeff"):
        raise R2Error("json:unexpected-bom")
    try:
        parsed = json.loads(data, object_pairs_hook=_duplicate_guard,
                            parse_constant=_reject_constant)
    except R2Error:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise R2Error(f"json:unreadable:{type(exc).__name__}") from exc
    _check_tree(parsed)
    return parsed


def _read_bounded(path: Path, limit: int) -> bytes:
    # Read no more than limit+1 bytes, no unbounded read if file grows.
    with path.open("rb") as fp:
        result = fp.read(limit + 1)
    if len(result) > limit:
        raise R2Error("input:byte-limit")
    return result


def sha256_bytes(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def verify_bundle_r2(bundle: Any, pin: Any) -> dict[str, Any]:
    """Validate content closure, pinned input digest and PASS gate state.

    pin is ASSUMED consumer-authoritative by this in-memory API. For file-based
    use, always use CLI or independently authenticate the pin bytes first.
    """
    if not isinstance(bundle, Mapping) or not isinstance(pin, Mapping):
        raise R2Error("input:not-mappings")
    _check_tree(bundle)
    _check_tree(pin)
    if not isinstance(pin, dict):
        pin = dict(pin)
    if not isinstance(bundle, dict):
        bundle = dict(bundle)
    if pin.get("schema_name") != "ARKTrustedGatePin" or pin.get("schema_version") != "2.0.0":
        raise R2Error("pin:r2-schema-required")
    if set(pin) != {
        "schema_name", "schema_version", "gate_id", "claim_id", "run_id",
        "profile_id", "profile_version", "profile_digest", "input_manifest",
        "input_digest", "gate_report_digest", "scope_policy",
    }:
        raise R2Error("pin:r2-field-set-mismatch")
    report_digest = pin["gate_report_digest"]
    if not isinstance(report_digest, str) or not SHA_RE.fullmatch(report_digest):
        raise R2Error("pin:gate-report-digest-invalid")
    declared_digest = pin["input_digest"]
    if not isinstance(declared_digest, str) or not SHA_RE.fullmatch(declared_digest):
        raise R2Error("pin:input-digest-invalid")
    if not isinstance(pin["input_manifest"], list):
        raise R2Error("pin:input-manifest-not-array")
    if len(pin["input_manifest"]) > MAX_GATE_DOCUMENTS:
        raise R2Error("pin:too-many-documents")
    # Delegate profile/identity/full-document recomputation to the upstream-compatible R1.
    base_pin = {k: v for k, v in pin.items() if k not in ("input_digest", "gate_report_digest")}
    base_pin["schema_version"] = "1.0.0"
    try:
        binding = verify_r1(bundle, base_pin)
    except (TypeError, ValueError, OverflowError, RecursionError, UnicodeError, KeyError) as exc:
        raise R2Error(f"upstream-binding-rejected:{exc}") from exc
    actual_digest = binding["input_digest"]
    if not hmac.compare_digest(declared_digest, actual_digest):
        raise R2Error("gate:expected-input-digest-mismatch")

    gate = bundle["gate_reports"][0]
    if gate.get("schema_name") != "GateReport":
        raise R2Error("gate:invalid-schema-name")
    if gate.get("result") != "PASS":
        raise R2Error("gate:not-pass")
    try:
        current_report_digest = project_digest(gate)
    except (TypeError, ValueError, OverflowError, UnicodeError, RecursionError) as exc:
        raise R2Error("gate:report-not-canonical") from exc
    if not hmac.compare_digest(report_digest, current_report_digest):
        raise R2Error("gate:trusted-report-digest-mismatch")
    # This confirms only the exact gate material is bound to consumer expectations.
    # SupersessionReports and scientific claims are evaluated by separate validators.
    return {
        "status": "GATE_INPUT_BOUND_TO_CONSUMER_PIN",
        "gate_id": binding["gate_id"],
        "run_id": binding["run_id"],
        "claim_id": binding["claim_id"],
        "profile_digest": binding["profile_digest"],
        "gate_report_digest": report_digest,
        "input_digest": binding["input_digest"],
        "input_count": binding["input_count"],
        "gate_result": "PASS",
        "gate_material_verification": "VERIFIED",
        "pin_authority": "ASSUMED_FROM_CALLER",
        "unverified_sections": sorted(set(bundle) - {
            "model_spec", "run_plan", "claim_card", "evidence_attestations",
            "gate_reports", "gate_input_profiles",
        }),
        "scientific_truth": "NOT_ESTABLISHED",
        "release_trust": "NOT_ESTABLISHED",
    }


def _check_output_is_not_input(out: Path, *inputs: Path) -> None:
    # Prevent overwrite of bundle/pin even via symlinks or hardlinks.
    target = out.resolve(strict=False)
    for inp in inputs:
        if target == inp.resolve(strict=False):
            raise R2Error("cli:output-aliases-input")
        try:
            if out.exists() and inp.exists() and os.path.samefile(out, inp):
                raise R2Error("cli:output-hardlink-aliases-input")
        except OSError as exc:
            raise R2Error(f"cli:unsafe-output-path:{exc}") from exc
    if out.is_symlink():
        raise R2Error("cli:output-symlink-forbidden")


def _atomic_report(out: Path, value: Mapping[str, Any]) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".ark-r2-", dir=out.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(value, f, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, out)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ARK R2 strict consumer-held gate preflight (not scientific/release approval)")
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--trusted-pin", type=Path, required=True)
    parser.add_argument("--expected-pin-sha256", required=True,
                        help="sha256:<64 lowercase hex> over EXACT trusted-pin file bytes; from independently managed configuration")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        _check_output_is_not_input(args.out, args.bundle, args.trusted_pin)
    except R2Error as exc:
        print(f"ERROR: {exc}; no output file overwritten", file=sys.stderr)
        return 3
    result: dict[str, Any]
    rc = 2
    try:
        if not SHA_RE.fullmatch(args.expected_pin_sha256):
            raise R2Error("pin:expected-pin-sha256-invalid")
        pin_bytes = _read_bounded(args.trusted_pin, MAX_PIN_BYTES)
        if not hmac.compare_digest(sha256_bytes(pin_bytes), args.expected_pin_sha256):
            raise R2Error("pin:out-of-band-file-digest-mismatch")
        pin = strict_json(pin_bytes, max_bytes=MAX_PIN_BYTES)
        bundle = strict_json(_read_bounded(args.bundle, MAX_BUNDLE_BYTES), max_bytes=MAX_BUNDLE_BYTES)
        result = verify_bundle_r2(bundle, pin)
        result["pin_authority"] = "FILE_DIGEST_MATCHED_OUT_OF_BAND_EXPECTATION"
        rc = 0
    except (R2Error, OSError, UnicodeError, ValueError, OverflowError, RecursionError, TypeError) as exc:
        result = {"status": "REJECT", "reason": str(exc), "scientific_truth": "NOT_ESTABLISHED", "release_trust": "NOT_ESTABLISHED"}
    try:
        _atomic_report(args.out, result)
    except (OSError, TypeError, ValueError) as exc:
        print(json.dumps({"status": "REJECT", "reason": f"report-write-failed:{exc}"}), file=sys.stderr)
        return 3
    print(json.dumps(result, sort_keys=True, ensure_ascii=False))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
