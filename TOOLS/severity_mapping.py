from __future__ import annotations

from typing import Dict, Iterable

HARD_PREFIXES = ("NEG.KERNEL.", "NEG.CONTRACT.")
HARD_EXACT = {
    "NEG.ARCHIVE.SCHEMA_FAIL",
    "NEG.ARCHIVE.SCHEMATRON_FAIL",
    "NEG.ARCHIVE.MISSING_FILE",
    "NEG.ARCHIVE.CHECKSUM_FAIL",
    "NEG.ARCHIVE.CASING_FAIL",
    "NEG.ARCHIVE.MANIFEST_MISMATCH",
    "NEG.REPORT.SCHEMA_INVALID",
    "NEG.ROOT.UNKNOWN_METHOD",
    "NEG.BASELINE.NOT_FOUND",
    "NEG.BASELINE.MULTIPLE_MATCHES",
    "NEG.BASELINE.INCOMPATIBLE_VERSION",
}
SOFT_PREFIXES = ("NEG.CALIB.", "NEG.QA.", "NEG.DYN.", "NEG.METRIC.", "NEG.CONTRADICTION.")
SOFT_EXACT = {
    "NEG.EVENT.NO_BRACKET",
    "NEG.EVENT.BOUNDARY_UNSTABLE",
    "NEG.BASELINE.INVALID_SCOPE",
    "NEG.BASELINE.INVALID_METRIC_SNAPSHOT",
    "NEG.BASELINE.REGISTRY_MISMATCH",
}
WARN_PREFIXES = ("NEG.PROV.",)
WARN_EXACT = {
    "NEG.EVENT.SHORT_WINDOW",
    "NEG.EVENT.HYSTERESIS_REQUIRED",
    "NEG.EVENT.MERGE_AMBIGUOUS",
}
NON_DOWNGRADABLE = {
    "NEG.REPORT.SCHEMA_INVALID",
    "NEG.ROOT.UNKNOWN_METHOD",
    "NEG.BASELINE.NOT_FOUND",
    "NEG.BASELINE.MULTIPLE_MATCHES",
    "NEG.ARCHIVE.SCHEMA_FAIL",
    "NEG.ARCHIVE.SCHEMATRON_FAIL",
}

# Kernel integrity is the reproducibility anchor: missing kernel files are
# already unroutable HARD failures, so their payload findings (hash, version,
# readability) are locked with the same strictness.
NON_DOWNGRADABLE_PREFIXES = ("NEG.KERNEL.",)
OVERRIDE_SEVERITIES = {"HARD_FAIL", "SOFT_FAIL", "WARNING"}

def is_non_downgradable(neg_id: str) -> bool:
    return neg_id in NON_DOWNGRADABLE or neg_id.startswith(NON_DOWNGRADABLE_PREFIXES)

def classify_neg_id(neg_id: str, policy: Dict|None=None, known_issue_ids: Iterable[str]=(), waived_issue_ids: Iterable[str]=(), strict_mode: bool=True) -> str:
    policy = policy or {}
    # NON_DOWNGRADABLE ids are immune to every policy lever: a waiver or a
    # known-issue entry is a downgrade just like a severity override.
    if not is_non_downgradable(neg_id):
        if neg_id in waived_issue_ids:
            return "WAIVED_ISSUE"
        if neg_id in known_issue_ids:
            return "KNOWN_ISSUE"
        overrides = policy.get("severity_overrides", {})
        if neg_id in overrides:
            if overrides[neg_id] not in OVERRIDE_SEVERITIES:
                raise ValueError(f"invalid severity override for {neg_id}: {overrides[neg_id]!r}")
            return overrides[neg_id]
    if neg_id in HARD_EXACT or neg_id.startswith(HARD_PREFIXES):
        return "HARD_FAIL"
    if neg_id in SOFT_EXACT or neg_id.startswith(SOFT_PREFIXES):
        return "SOFT_FAIL"
    if neg_id in WARN_EXACT or neg_id.startswith(WARN_PREFIXES):
        return "WARNING"
    return "HARD_FAIL" if strict_mode else "SOFT_FAIL"
