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

from severity_mapping import classify_neg_id, is_non_downgradable

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
# CLI verdict when the policy cannot be established (issue #33); HARD and
# non-downgradable in severity_mapping -- a policy cannot waive its own absence.
POLICY_UNREADABLE = "NEG.POLICY.UNREADABLE"
# Opt-in CLI exit codes (``--strict-exit``, issue #37). 2 matches argparse's own
# usage-error code, so every "the tool did not run cleanly" case shares one code
# and the verdicts keep theirs.
EXIT_OK = 0
EXIT_REJECT = 1
EXIT_TOOL_ERROR = 2
EXIT_REVIEW = 3
_STRICT_EXIT_BY_STATUS = {
    "ACCEPT": EXIT_OK,
    "ACCEPT_WITH_NOTES": EXIT_OK,
    "REJECT": EXIT_REJECT,
    "REVIEW": EXIT_REVIEW,
}


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
    non-downgradable neg id (NON_DOWNGRADABLE set or ``NEG.KERNEL.*``) is
    refused (fail-closed): such ids must never be softened by policy.
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
        if not isinstance(severity, str) or severity not in ALLOWED_SEVERITIES:
            raise PolicyError(
                f"severity_overrides[{neg_id}] = {severity!r} not in {sorted(ALLOWED_SEVERITIES)}"
            )
        if is_non_downgradable(neg_id):
            raise PolicyError(f"refusing non-downgradable override of {neg_id}")

    for key in ("known_issues", "waivers"):
        value = policy.get(key, [])
        if not isinstance(value, list) or not all(isinstance(x, str) and x for x in value):
            raise PolicyError(f"{key} must be a list of non-empty strings")
        locked = sorted(x for x in set(value) if is_non_downgradable(x))
        if locked:
            raise PolicyError(f"refusing {key} entry for non-downgradable id(s): {locked}")
    return policy


def load_policy(path):
    """Load + validate a policy file. Fail-closed on missing/malformed input."""
    try:
        doc = read_json(path)
    except FileNotFoundError:
        raise PolicyError(f"policy file not found: {path}")
    except (OSError, ValueError, RecursionError) as exc:
        # ValueError: JSONDecodeError, UnicodeDecodeError, int-digit limit;
        # RecursionError: nesting deeper than the recursion limit.
        raise PolicyError(f"policy file unreadable ({path}): {type(exc).__name__}: {exc}")
    return validate_policy_shape(doc)


def _resolve_policy(run_dir, policy):
    """Return an effective, validated policy dict.

    ``policy is None`` -> load ``<run_dir>/policy.json`` if it is stored with
    exactly that name, else {}. An explicit dict is validated defensively.

    Presence is decided against the stored names (``os.listdir``), not with
    ``os.path.isfile``: on NTFS/APFS ``isfile`` says yes for ``policy.json`` when
    only ``POLICY.json`` is stored, so the effective policy -- and with it the
    waivers -- would depend on the host file system (same class as A1).
    """
    if policy is None:
        default_path = os.path.join(run_dir, DEFAULT_POLICY_FILENAME)
        try:
            stored = os.listdir(run_dir) if os.path.isdir(run_dir) else []
        except OSError as exc:
            # Cannot tell whether a policy (with waivers) exists: fail closed.
            raise PolicyError(f"run dir not listable ({run_dir}): {exc}")
        if DEFAULT_POLICY_FILENAME in stored and os.path.isfile(default_path):
            return load_policy(default_path)
        return {}
    return validate_policy_shape(policy)


def validate_json_against_schema(instance, schema_path):
    schema = read_json(schema_path)
    Draft202012Validator(schema, format_checker=strict_format_checker()).validate(instance)


def check_root_plan(plan):
    """Check the root-finding method pinned in ``kernel.plan.json``.

    The method is part of the run's reproducible execution plan (REGISTRY_POLICY:
    exact pinning in kernel.plan wins), not of the gate policy. Absent
    ``payload.root`` keeps the default ``brentq``; a present entry without METHOD, a malformed or
    non-allowlisted entry is a hard error (ROOT_FINDING_v1).
    """
    payload = plan.get("payload") if isinstance(plan, dict) else None
    if not isinstance(payload, dict) or "root" not in payload:
        return []
    root = payload["root"]
    method = root.get("METHOD") if isinstance(root, dict) else None
    return [] if isinstance(method, str) and method in ROOT_ALLOWED_METHODS else ["NEG.ROOT.UNKNOWN_METHOD"]


REQUIRED_KERNEL_FILES = (
    "kernel.model.json", "kernel.plan.json", "kernel.events.json", "kernel.schema.json", "kernel.env.json",
)


def _is_kernel_name(fn):
    return fn.startswith("kernel.") and fn.endswith(".json")


# Spec-defined kernel names beyond the required five (BASELINE_POLICY_v1:
# ``kernel.baseline.json``). Their exact spelling is enforced like the required
# ones, so ``kernel.BASELINE.json`` cannot pass as a merely "other" kernel.
OPTIONAL_KERNEL_FILES = ("kernel.baseline.json",)
CANONICAL_KERNEL_FILES = REQUIRED_KERNEL_FILES + OPTIONAL_KERNEL_FILES
_CANONICAL_FOLDED = {f.casefold() for f in CANONICAL_KERNEL_FILES}


def _is_kernel_case_variant(fn):
    """True for a stored name that deviates from a kernel name only by case.

    Covers (a) a case variant of a canonical name (``kernel.PLAN.json``,
    ``kernel.BASELINE.json``) and
    (b) a name that is a kernel file only when case is ignored
    (``KERNEL.plan.json``, ``kernel.x.JSON``), which the payload loop would skip.
    """
    folded = fn.casefold()
    if folded in _CANONICAL_FOLDED:
        return fn not in CANONICAL_KERNEL_FILES
    return folded.startswith("kernel.") and folded.endswith(".json") and not _is_kernel_name(fn)


def list_kernel_dir(run_dir):
    """Return the stored names in ``<run_dir>/kernels`` (``[]`` if absent).

    Names come from ``os.listdir``, i.e. with the spelling stored on disk. Presence
    checks must compare against this list, NOT use ``os.path.exists``: on
    case-insensitive file systems (Windows NTFS, macOS APFS default) ``exists`` says
    yes for ``kernel.plan.json`` when only ``kernel.PLAN.json`` is stored, while the
    payload loop compares names case-sensitively -> the plan would count as present
    but its root method would never be checked (gate bypass). Raises ``OSError``
    if the directory exists but cannot be listed.
    """
    kernels_dir = os.path.join(run_dir, "kernels")
    if not os.path.isdir(kernels_dir):
        return []
    # Same rule for the directory itself: ``Kernels/`` must not pass on NTFS/APFS
    # while it is absent on Linux (the verdict must not depend on the host FS).
    if "kernels" not in os.listdir(run_dir):
        return []
    return sorted(os.listdir(kernels_dir))


def check_kernel_files(run_dir, names=None):
    """Structural kernel-file checks against the EXACT (case-sensitive) stored names.

    - a required name not stored with exactly that spelling -> ``NEG.KERNEL.MISSING_<X>``
    - any stored name that is a kernel file only when case is ignored
      (``kernel.PLAN.json``, ``KERNEL.plan.json``, ``Kernel.Plan.JSON``, also next
      to an exact-name file on a case-sensitive FS) -> ``NEG.KERNEL.NAME_CASE_MISMATCH``
    """
    if names is None:
        names = list_kernel_dir(run_dir)
    stored = set(names)
    neg = []
    for f in REQUIRED_KERNEL_FILES:
        if f not in stored:
            neg.append("NEG.KERNEL.MISSING_" + f.split(".")[1].upper())
    kernelish = [fn for fn in stored if fn.casefold().startswith("kernel.") and fn.casefold().endswith(".json")]
    case_duplicates = len({fn.casefold() for fn in kernelish}) < len(kernelish)
    if case_duplicates or any(_is_kernel_case_variant(fn) for fn in kernelish):
        neg.append("NEG.KERNEL.NAME_CASE_MISMATCH")
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


def _run_id(run_dir, _path=os.path):
    """Run id = last component of ``run_dir`` under the HOST path semantics.

    ``normpath`` drops trailing separators -- on Windows both ``\\`` and ``/``
    -- so ``run``, ``run/`` and ``run\\`` name the same run (issue #34: a
    trailing backslash used to yield an empty id and a REJECT). It stays a pure
    function of the argument string (no cwd lookup, unlike ``abspath``), so the
    id is reproducible. ``PureWindowsPath`` is deliberately NOT used: on POSIX a
    backslash is a legal file-name character, and the id must name the
    directory that is actually opened, i.e. follow ``os.path``.
    ``_path`` exists only so tests can pin both ``ntpath`` and ``posixpath``.

    An empty ``run_dir`` stays an empty id (``normpath("")`` would be ``"."``),
    so it keeps failing the report schema (``minLength: 1``) -> REJECT, instead
    of silently validating the current working directory as run ``"."``.
    """
    raw = os.fspath(run_dir)
    if not raw:
        return ""
    return _path.basename(_path.normpath(raw))


def validate_run(run_dir, policy=None):
    policy = _resolve_policy(run_dir, policy)
    known_issue_ids = policy.get("known_issues", [])
    waived_issue_ids = policy.get("waivers", [])
    hard_fail = []
    soft_fail = []
    warnings = []
    known_issues = []
    report = {
        "run_id": _run_id(run_dir),
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

    kernels_dir = os.path.join(run_dir, "kernels")
    try:
        names = list_kernel_dir(run_dir)
    except OSError:
        # Unlistable kernels dir: fail closed with a report, not a crash.
        names = []
        hard_fail.append("NEG.KERNEL.UNREADABLE")

    # Missing / case-mismatched kernel files are structural HARD failures by definition.
    hard_fail.extend(check_kernel_files(run_dir, names))

    for fn in names:
        if _is_kernel_name(fn):
            try:
                obj = read_json(os.path.join(kernels_dir, fn))
            except (OSError, ValueError, RecursionError):
                # Fail closed with a report instead of crashing without one.
                # ValueError covers JSONDecodeError, UnicodeDecodeError and the
                # int-digit limit (int_max_str_digits); RecursionError covers
                # nesting deeper than the interpreter's recursion limit.
                obj = None
            for neg in check_kernel_payload(obj):
                route(neg)
            if fn == "kernel.plan.json":
                for neg in check_root_plan(obj):
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


def policy_unreadable_report(run_dir):
    """REJECT report for a run whose policy cannot be established (issue #33).

    ``validate_run`` raises ``PolicyError`` when the policy is missing, unreadable
    or malformed, or when ``run_dir`` cannot be listed (so the presence of a
    ``policy.json`` with waivers cannot be decided). The API keeps raising; the
    CLI turns it into this report so a caller always gets a verdict on disk and
    a previous report at the same path is replaced when that write succeeds
    (see ``main`` for the write-failure case).
    """
    report = {
        "run_id": _run_id(run_dir),
        "created_utc": utc_now(),
        "status": "REJECT",
        "hard_fail": [POLICY_UNREADABLE],
        "soft_fail": [],
        "warnings": [],
        "known_issues": [],
        "metrics": [],
        "gate_results": [],
    }
    try:
        report_schema_validator().validate(report)
    except ValidationError:
        report["hard_fail"].append("NEG.REPORT.SCHEMA_INVALID")
    return report


def strict_exit_code(status):
    """Exit code of a report status under ``--strict-exit`` (issue #37).

    Fail-closed: a status outside the report schema's enum -- including a
    non-string such as a list -- maps to REJECT instead of raising.
    """
    if not isinstance(status, str):
        return EXIT_REJECT
    return _STRICT_EXIT_BY_STATUS.get(status, EXIT_REJECT)


def _discard_stale_report(out):
    """Remove a report left at ``out`` by an earlier run, where the FS allows it."""
    try:
        os.remove(out)
    except OSError:
        pass


def main(argv=None):
    """CLI entry point. Returns the process exit code.

    0: a report was written (whatever its status). 1: the policy could not be
    established -- a REJECT report with ``NEG.POLICY.UNREADABLE`` was written --
    the report itself could not be written, or the validator failed internally
    (e.g. a missing schema file; no report is written). 2: argparse usage error.
    When no report is written, a stale report at the output path is removed
    where possible; if it cannot be removed either (read-only or locked file on
    Windows) it stays and only the exit code signals the failure.

    With ``--strict-exit`` the code also carries the verdict (issue #37):
    0 ACCEPT/ACCEPT_WITH_NOTES, 1 REJECT, 2 tool error (policy error, report
    not written, internal failure; same code as an argparse usage error),
    3 REVIEW.
    """
    import argparse
    import sys
    import traceback

    ap = argparse.ArgumentParser(description="ARK run-gate validator (deterministic).")
    ap.add_argument("--run", required=True)
    ap.add_argument("--out", default=None)
    ap.add_argument(
        "--policy",
        default=None,
        help="Explicit policy file (severity_overrides/known_issues/waivers). "
        "Defaults to <run>/policy.json if present.",
    )
    ap.add_argument(
        "--strict-exit",
        action="store_true",
        help="Exit code carries the verdict: 0 ACCEPT/ACCEPT_WITH_NOTES, 1 REJECT, "
        "2 tool error, 3 REVIEW. Default: 0 whenever a report was written.",
    )
    args = ap.parse_args(argv)
    tool_error = EXIT_TOOL_ERROR if args.strict_exit else 1
    out = args.out or os.path.join(args.run, "reports", "gate_report.json")
    rc = 0
    try:
        try:
            loaded_policy = load_policy(args.policy) if args.policy else None
            report = validate_run(args.run, policy=loaded_policy)
        except PolicyError as exc:
            print(f"validate_run: policy error -> REJECT: {exc}", file=sys.stderr)
            report = policy_unreadable_report(args.run)
            rc = tool_error
    except Exception:  # noqa: BLE001 - a crash is a tool error, never a verdict
        # Without this an uncaught exception exits 1 (= REJECT under
        # --strict-exit) and leaves an older report -- possibly ACCEPT -- in place.
        traceback.print_exc()
        print("validate_run: internal error, no report written", file=sys.stderr)
        _discard_stale_report(out)
        return tool_error
    try:
        out_dir = os.path.dirname(out)
        if out_dir:  # "--out report.json" has no directory part
            os.makedirs(out_dir, exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, sort_keys=True)
    except Exception as exc:  # noqa: BLE001 - OSError, or a partial dump
        print(f"validate_run: cannot write report {out}: {exc}", file=sys.stderr)
        _discard_stale_report(out)
        return tool_error
    print(out)
    if args.strict_exit and rc == 0:
        return strict_exit_code(report["status"])
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
