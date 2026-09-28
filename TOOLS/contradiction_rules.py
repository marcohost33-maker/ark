from __future__ import annotations
import math
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

ALLOWED_SEVERITIES = {"HARD_FAIL", "SOFT_FAIL", "WARNING"}
ALLOWED_COMPARISONS = {"gt", "ge", "lt", "le", "eq", "ne"}
ALLOWED_LOGICAL = {"all", "any", "not"}

@dataclass(frozen=True)
class RuleIssue:
    code: str
    message: str
    rule_id: str | None = None

@dataclass(frozen=True)
class RuleHit:
    rule_id: str
    neg_id: str
    severity: str
    summary: str

def _is_metric_ref(x: Any) -> bool:
    return isinstance(x, str) and (x.startswith("METRIC.") or x.startswith("baseline.METRIC."))

def _validate_expr_shape(expr: Any, rule_id: str|None, issues: List[RuleIssue]) -> None:
    """Validate the whole expression tree (not only the root node).

    Structural validity must not depend on metric values: a malformed branch
    behind a short-circuiting ``all``/``any`` is still reported.
    """
    if not isinstance(expr, dict) or len(expr) != 1:
        issues.append(RuleIssue("NEG.CONTRADICTION.INVALID_STRUCTURE", "Expression must be a one-key dict", rule_id))
        return
    op, value = next(iter(expr.items()))
    if op not in ALLOWED_COMPARISONS | ALLOWED_LOGICAL:
        issues.append(RuleIssue("NEG.CONTRADICTION.UNKNOWN_OPERATOR", f"Unknown operator: {op}", rule_id))
        return
    if op in ALLOWED_COMPARISONS:
        if not isinstance(value, list) or len(value) != 2:
            issues.append(RuleIssue("NEG.CONTRADICTION.INVALID_STRUCTURE", f"{op} expects list length 2", rule_id))
            return
        for operand in value:
            if not (_is_numeric_literal(operand) or _is_metric_ref(operand)):
                # repr() of a huge int can itself raise (int max str digits).
                shown = "integer out of float range" if isinstance(operand, int) and not isinstance(operand, bool) else repr(operand)
                issues.append(RuleIssue("NEG.CONTRADICTION.TYPE_MISMATCH", f"Invalid operand: {shown}", rule_id))
    elif op in {"all", "any"}:
        if not isinstance(value, list):
            issues.append(RuleIssue("NEG.CONTRADICTION.INVALID_STRUCTURE", f"{op} expects list", rule_id))
            return
        for sub in value:
            _validate_expr_shape(sub, rule_id, issues)
    else:  # not
        _validate_expr_shape(value, rule_id, issues)

def _is_numeric_literal(x: Any) -> bool:
    # bool is an int subclass in Python, but JSON true/false are not numbers.
    if isinstance(x, bool) or not isinstance(x, (int, float)):
        return False
    try:
        # JSON integers are unbounded; one beyond double range is not comparable.
        return math.isfinite(float(x))
    except OverflowError:
        return False

def _collect_metric_refs(expr: Any, out: set[str]) -> None:
    if isinstance(expr, dict):
        for _, v in expr.items():
            _collect_metric_refs(v, out)
    elif isinstance(expr, list):
        for item in expr:
            _collect_metric_refs(item, out)
    elif _is_metric_ref(expr):
        out.add(expr)

def _resolve_operand(x: Any, metrics: Dict[str, float], baseline: Dict[str, float]) -> float:
    if _is_numeric_literal(x):
        return float(x)
    if isinstance(x, str):
        if x.startswith("baseline.METRIC."):
            key = x[len("baseline."):]
            if key not in baseline:
                raise KeyError(f"Missing baseline metric: {key}")
            return float(baseline[key])
        if x.startswith("METRIC."):
            if x not in metrics:
                raise KeyError(f"Missing metric: {x}")
            return float(metrics[x])
    raise TypeError(f"Invalid operand: {x!r}")

def _eval_expr(expr: Dict[str, Any], metrics: Dict[str, float], baseline: Dict[str, float]) -> bool:
    op, value = next(iter(expr.items()))
    if op in ALLOWED_COMPARISONS:
        a = _resolve_operand(value[0], metrics, baseline)
        b = _resolve_operand(value[1], metrics, baseline)
        return {"gt": a > b, "ge": a >= b, "lt": a < b, "le": a <= b, "eq": a == b, "ne": a != b}[op]
    if op == "all":
        return all(_eval_expr(v, metrics, baseline) for v in value)
    if op == "any":
        return any(_eval_expr(v, metrics, baseline) for v in value)
    if op == "not":
        return not _eval_expr(value, metrics, baseline)
    raise ValueError(f"Unknown operator: {op}")

def validate_rule_structure(rule: Dict[str, Any], known_metrics: set[str], known_baseline_metrics: set[str]) -> List[RuleIssue]:
    issues: List[RuleIssue] = []
    if not isinstance(rule, dict):
        return [RuleIssue("NEG.CONTRADICTION.INVALID_STRUCTURE", "Rule must be an object")]
    rule_id = rule.get("rule_id")
    missing = {"rule_id", "when", "neg_id", "severity", "summary"} - set(rule.keys())
    if missing:
        issues.append(RuleIssue("NEG.CONTRADICTION.INVALID_STRUCTURE", f"Missing keys: {sorted(missing)}", rule_id))
        return issues
    if not isinstance(rule["severity"], str) or rule["severity"] not in ALLOWED_SEVERITIES:
        issues.append(RuleIssue("NEG.CONTRADICTION.INVALID_SEVERITY", f"Invalid severity: {rule['severity']}", rule_id))
    _validate_expr_shape(rule["when"], rule_id, issues)
    refs: set[str] = set()
    _collect_metric_refs(rule["when"], refs)
    for ref in refs:
        if ref.startswith("baseline.METRIC."):
            key = ref[len("baseline."):]
            if key not in known_baseline_metrics:
                issues.append(RuleIssue("NEG.CONTRADICTION.MISSING_BASELINE", f"Unknown baseline metric: {key}", rule_id))
        elif ref.startswith("METRIC.") and ref not in known_metrics:
            issues.append(RuleIssue("NEG.CONTRADICTION.UNKNOWN_METRIC", f"Unknown metric: {ref}", rule_id))
    if not issues:
        try:
            dummy_metrics = {k: 1.0 for k in known_metrics}
            dummy_baseline = {k: 1.0 for k in known_baseline_metrics}
            _eval_expr(rule["when"], dummy_metrics, dummy_baseline)
        except TypeError as e:
            issues.append(RuleIssue("NEG.CONTRADICTION.TYPE_MISMATCH", str(e), rule_id))
        except KeyError as e:
            issues.append(RuleIssue("NEG.CONTRADICTION.UNKNOWN_METRIC", str(e), rule_id))
        except ValueError as e:
            issues.append(RuleIssue("NEG.CONTRADICTION.INVALID_STRUCTURE", str(e), rule_id))
    return issues

def evaluate_rules(rules: List[Dict[str, Any]], metrics: Dict[str, float], baseline: Dict[str, float]) -> Tuple[List[RuleHit], List[RuleIssue]]:
    hits: List[RuleHit] = []
    issues: List[RuleIssue] = []
    known_metrics = set(metrics.keys())
    known_baseline_metrics = set(baseline.keys())
    for rule in rules:
        if not isinstance(rule, dict):
            issues.append(RuleIssue("NEG.CONTRADICTION.INVALID_STRUCTURE", "Rule must be an object"))
            continue
        rule_issues = validate_rule_structure(rule, known_metrics, known_baseline_metrics)
        issues.extend(rule_issues)
        if rule_issues:
            continue
        try:
            if _eval_expr(rule["when"], metrics, baseline):
                hits.append(RuleHit(rule["rule_id"], rule["neg_id"], rule["severity"], rule["summary"]))
        except Exception as e:
            issues.append(RuleIssue("NEG.CONTRADICTION.EVAL_ERROR", str(e), rule.get("rule_id")))
    return hits, issues
