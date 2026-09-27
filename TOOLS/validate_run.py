#!/usr/bin/env python3
"""Deterministic run-gate validator.

Hardening (issue #18):
- Policy is loaded **explicitly** from a deterministic file location
  (``<run_dir>/policy.json``) or an explicit ``--policy PATH`` CLI parameter,
  instead of an internal ``policy = {}``. A malformed policy fails closed
  (``PolicyError``) rather than being silently ignored.
- Report self-validation uses ``Draft202012Validator`` + an explicit
  ``FormatChecker`` that enforces ``format: date-time`` (RFC 3339, timezone
  required). The stock ``jsonschema`` install ships no ``date-time`` checker,
  so the format is registered here deterministically (stdlib only) — otherwise
  ``format: date-time`` in the schemas would never actually be enforced.

Default behaviour is preserved: when no policy file is present, the effective
policy is ``{}`` and classification is identical to the pre-hardening tool.
"""
import json
import os
import re
from datetime import datetime, timezone

from jsonschema import Draft202012Validator, FormatChecker, ValidationError

from severity_mapping import NON_DOWNGRADABLE, classify_neg_id

# Official SemVer 2.0.0 regex (semver.org, "Backus-Naur Form Grammar" appendix).
# Forbids leading zeros in numeric prerelease identifiers and empty identifiers,
# which the previous pattern wrongly accepted (e.g. 1.2.3-0123, 1.0.0-alpha..).
SEMVER_RE = re.compile(
    r"^(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)"
    r"(?:-(?P<prerelease>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)"
    r"(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    r"(?:\+(?P<buildmetadata>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"
)
ROOT_ALLOWED_METHODS = {"bisect", "brentq", "brenth", "ridder", "toms748"}

ALLOWED_SEVERITIES = {"HARD_FAIL", "SOFT_FAIL", "WARNING"}
# Deterministic default policy location, relative to the run directory.
DEFAULT_POLICY_FILENAME = "policy.json"
_ALLOWED_POLICY_KEYS = {"severity_overrides", "known_issues", "waivers"}


class PolicyError(ValueError):
    """Raised when a policy document is structurally invalid (fail-closed)."""


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def read_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _check_date_time(value):
    """RFC 3339 date-time check (timezone required). Raises ValueError if invalid."""
    if not isinstance(value, str):
        return True  # non-strings are rejected by the schema's `type` keyword
    text = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
    parsed = datetime.fromisoformat(text)  # raises ValueError on malformed input
    if parsed.tzinfo is None:
        raise ValueError("date-time requires an explicit timezone offset")
    return True


def strict_format_checker():
    """FormatChecker with an explicit, dependency-free ``date-time`` enforcer.

    ``jsonschema`` only enforces ``format: date-time`` when an optional
    third-party validator (``rfc3339-validator``) is installed; the ARK CI env
    does not ship it, so we register the check here to make the schemas'
    ``format: date-time`` load-bearing and deterministic.
    """
    checker = FormatChecker()
    checker.checks("date-time", raises=(ValueError,))(_check_date_time)
    return checker


def report_schema_validator():
    """Draft 2020-12 validator for gate reports with date-time format enforcement."""
    schema_path = os.path.join(
        os.path.dirname(__file__), "..", "SCHEMAS", "gate_report.schema.json"
    )
    schema = read_json(schema_path)
    return Draft202012Validator(schema, format_checker=strict_format_checker())


def validate_policy_shape(policy):
    """Validate a policy document; raise ``PolicyError`` on any malformed shape.

    Allowed keys: ``severity_overrides`` (map neg_id -> severity in
    {HARD_FAIL, SOFT_FAIL, WARNING}), ``known_issues`` (list[str]),
    ``waivers`` (list[str]). Overriding, waiving or known-issue-listing a
    NON_DOWNGRADABLE neg id is refused (fail-closed): such ids must never be
    softened by policy.
    """
    if not isinstance(policy, dict):
        raise PolicyError(f"policy must be an object, got {type(policy).__name__}")
    unknown = set(policy) - _ALLOWED_POLICY_KEYS
    if unknown:
        raise PolicyError(f"unknown policy key(s): {sorted(unknown)}")

    overrides = policy.get("severity_overrides", {})
    if not isinstance(overrides, dict):
        raise PolicyError("severity_overrides must be an object")
    for neg_id, severity in overrides.items():
        if not isinstance(neg_id, str) or not neg_id:
            raise PolicyError(f"severity_overrides key must be a non-empty string: {neg_id!r}")
        if severity not in ALLOWED_SEVERITIES:
            raise PolicyError(
                f"severity_overrides[{neg_id}] = {severity!r} not in {sorted(ALLOWED_SEVERITIES)}"
            )
        if neg_id in NON_DOWNGRADABLE:
            raise PolicyError(f"refusing non-downgradable override of {neg_id}")

    for key in ("known_issues", "waivers"):
        value = policy.get(key, [])
        if not isinstance(value, list) or not all(isinstance(x, str) and x for x in value):
            raise PolicyError(f"{key} must be a list of non-empty strings")
        locked = sorted(set(value) & NON_DOWNGRADABLE)
        if locked:
            raise PolicyError(f"refusing {key} entry for non-downgradable id(s): {locked}")
    return policy


def load_policy(path):
    """Load + validate a policy file. Fail-closed on missing/malformed input."""
    try:
        doc = read_json(path)
    except FileNotFoundError:
        raise PolicyError(f"policy file not found: {path}")
    except (OSError, json.JSONDecodeError) as exc:
        raise PolicyError(f"policy file unreadable ({path}): {exc}")
    return validate_policy_shape(doc)


def _resolve_policy(run_dir, policy):
    """Return an effective, validated policy dict.

    ``policy is None`` -> load ``<run_dir>/policy.json`` if it exists, else {}.
    An explicit dict is validated defensively.
    """
    if policy is None:
        default_path = os.path.join(run_dir, DEFAULT_POLICY_FILENAME)
        if os.path.isfile(default_path):
            return load_policy(default_path)
        return {}
    return validate_policy_shape(policy)


def validate_json_against_schema(instance, schema_path):
    schema = read_json(schema_path)
    Draft202012Validator(schema, format_checker=strict_format_checker()).validate(instance)


def check_root_policy(policy):
    method = policy.get("ROOT", {}).get("METHOD", "brentq")
    return [] if method in ROOT_ALLOWED_METHODS else ["NEG.ROOT.UNKNOWN_METHOD"]


def check_kernel_files(run_dir):
    req = ["kernel.model.json", "kernel.plan.json", "kernel.events.json", "kernel.schema.json", "kernel.env.json"]
    neg = []
    for f in req:
        if not os.path.exists(os.path.join(run_dir, "kernels", f)):
            neg.append("NEG.KERNEL.MISSING_" + f.split(".")[1].upper())
    return neg


def check_kernel_payload(obj):
    if not isinstance(obj, dict):
        return ["NEG.KERNEL.UNREADABLE"]
    neg = []
    if not obj.get("content_hash"):
        neg.append("NEG.KERNEL.MISSING_HASH")
    if not obj.get("version"):
        neg.append("NEG.KERNEL.MISSING_VERSION")
    elif not isinstance(obj["version"], str) or not SEMVER_RE.match(obj["version"]):
        neg.append("NEG.KERNEL.INVALID_SEMVER")
    if "payload" not in obj:
        neg.append("NEG.KERNEL.MISSING_PAYLOAD")
    return neg


def validate_run(run_dir, policy=None):
    policy = _resolve_policy(run_dir, policy)
    known_issue_ids = policy.get("known_issues", [])
    waived_issue_ids = policy.get("waivers", [])
    hard_fail = []
    soft_fail = []
    warnings = []
    known_issues = []
    report = {
        "run_id": os.path.basename(run_dir.rstrip("/")),
        "created_utc": utc_now(),
        "status": "ACCEPT",
        "hard_fail": hard_fail,
        "soft_fail": soft_fail,
        "warnings": warnings,
        "known_issues": known_issues,
        "metrics": [],
        "gate_results": [],
    }

    def route(neg_id):
        cls = classify_neg_id(neg_id, policy, known_issue_ids, waived_issue_ids)
        if cls == "HARD_FAIL":
            hard_fail.append(neg_id)
        elif cls == "SOFT_FAIL":
            soft_fail.append(neg_id)
        elif cls == "WARNING":
            warnings.append(neg_id)
        else:  # KNOWN_ISSUE / WAIVED_ISSUE
            known_issues.append(neg_id)

    # Missing required kernel files are structural HARD failures by definition.
    hard_fail.extend(check_kernel_files(run_dir))

    kernels_dir = os.path.join(run_dir, "kernels")
    if os.path.isdir(kernels_dir):
        for fn in sorted(os.listdir(kernels_dir)):
            if fn.startswith("kernel.") and fn.endswith(".json"):
                try:
                    obj = read_json(os.path.join(kernels_dir, fn))
                except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                    # Fail closed with a report instead of crashing without one.
                    obj = None
                for neg in check_kernel_payload(obj):
                    route(neg)
    for neg in check_root_policy(policy):
        route(neg)

    if hard_fail:
        report["status"] = "REJECT"
    elif soft_fail:
        report["status"] = "REVIEW"
    elif warnings or known_issues:
        report["status"] = "ACCEPT_WITH_NOTES"

    try:
        report_schema_validator().validate(report)
    except ValidationError:
        report["status"] = "REJECT"
        report["hard_fail"].append("NEG.REPORT.SCHEMA_INVALID")
    return report


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="ARK run-gate validator (deterministic).")
    ap.add_argument("--run", required=True)
    ap.add_argument("--out", default=None)
    ap.add_argument(
        "--policy",
        default=None,
        help="Explicit policy file (severity_overrides/known_issues/waivers). "
        "Defaults to <run>/policy.json if present.",
    )
    args = ap.parse_args()
    loaded_policy = load_policy(args.policy) if args.policy else None
    report = validate_run(args.run, policy=loaded_policy)
    out = args.out or os.path.join(args.run, "reports", "gate_report.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, sort_keys=True)
    print(out)
