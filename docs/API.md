# ARK-Core — Tool API contracts

Input/output contracts of the deterministic tools in `TOOLS/` (ROADMAP Phase 3).
The contract source is `SPECS/`; this page states what the code does today and
where it enforces the spec. All tools are pure functions of their inputs: no clock
(except `validate_run`'s `created_utc`), no randomness, no network.

NEG IDs map to a severity via `severity_mapping` and to a run status by the
worst severity: any HARD_FAIL -> `REJECT`, else any SOFT_FAIL -> `REVIEW`,
else any WARNING / KNOWN_ISSUE / WAIVED_ISSUE -> `ACCEPT_WITH_NOTES`, else `ACCEPT`.

---

## `validate_run` — run gate

```python
validate_run(run_dir: str, policy: dict | None = None) -> dict   # gate report
```
CLI: `python TOOLS/validate_run.py --run DIR [--out FILE] [--policy FILE]`
(default output `DIR/reports/gate_report.json`, prints the path).

**Input.** `run_dir/kernels/kernel.{model,plan,events,schema,env}.json`, each an
object with `content_hash`, `version` (SemVer 2.0.0) and `payload`.
Policy: `policy=None` loads `run_dir/policy.json` if present, else `{}`; an
explicit dict is validated the same way. See `docs/POLICY_LOADING.md`.

**Output.** A report valid against `SCHEMAS/gate_report.schema.json`:
`run_id`, `created_utc`, `status`, `hard_fail`, `soft_fail`, `warnings`,
`known_issues`, `metrics`, `gate_results`.

| NEG ID | When |
|---|---|
| `NEG.KERNEL.MISSING_<NAME>` | a required kernel file is absent (always HARD, not routable) |
| `NEG.KERNEL.UNREADABLE` | kernel file is not valid UTF-8 JSON or not an object |
| `NEG.KERNEL.MISSING_HASH` / `MISSING_VERSION` / `MISSING_PAYLOAD` | field missing or empty |
| `NEG.KERNEL.INVALID_SEMVER` | `version` is not a SemVer 2.0.0 string |
| `NEG.REPORT.SCHEMA_INVALID` | the report fails its own schema (forces `REJECT`) |

**Errors.** `PolicyError` (fail-closed) for a missing/unreadable/malformed policy:
unknown keys, override values outside {HARD_FAIL, SOFT_FAIL, WARNING}, non-string
list entries, or any lever that names a NON_DOWNGRADABLE id.

*Known limitation:* `check_root_policy` reads `policy["ROOT"]["METHOD"]`, but
`ROOT` is not an allowed policy key, so `NEG.ROOT.UNKNOWN_METHOD` cannot be
raised through `validate_run` today. Whether the root method belongs in the
policy or in `kernel.plan.json` is an open design decision.

---

## `severity_mapping` — NEG ID -> severity

```python
classify_neg_id(neg_id, policy=None, known_issue_ids=(), waived_issue_ids=(),
                strict_mode=True) -> str
```
Returns one of `HARD_FAIL`, `SOFT_FAIL`, `WARNING`, `KNOWN_ISSUE`, `WAIVED_ISSUE`.

Precedence: NON_DOWNGRADABLE ids skip every policy lever (spec
`NEG_SEVERITY_MAPPING_v1`) -> waiver -> known issue -> `severity_overrides`
-> built-in HARD / SOFT / WARNING tables -> unknown id (`HARD_FAIL` in strict
mode, `SOFT_FAIL` otherwise). Raises `ValueError` for an override value outside
{HARD_FAIL, SOFT_FAIL, WARNING}.

---

## `provenance_validate` — PROV minimal graph

```python
validate_prov_min(doc: dict) -> list[str]   # sorted, de-duplicated NEG IDs
```
Input shape: `SCHEMAS/prov_min.schema.json` (`entities`, `activities`, `agents`,
`edges` with `type`/`src`/`dst`). Edge directions follow PROV-DM, see
`SPECS/PROVENANCE_MINIMAL_v1.md`. Empty list = valid.

NEG IDs: `MISSING_CORE_NODE`, `MISSING_ID`, `DUPLICATE_ID`, `UNKNOWN_EDGE_TYPE`,
`BROKEN_REF`, `MISSING_GENERATION_EDGE` (entity with != 1 `wasGeneratedBy`),
`MISSING_ASSOCIATION_EDGE` (activity without `wasAssociatedWith`); all prefixed
`NEG.PROV.` and mapped to WARNING.

---

## `contradiction_rules` — whitelist rule DSL

```python
evaluate_rules(rules: list[dict], metrics: dict[str, float],
               baseline: dict[str, float]) -> tuple[list[RuleHit], list[RuleIssue]]
validate_rule_structure(rule, known_metrics, known_baseline_metrics) -> list[RuleIssue]
```
A rule is `{rule_id, when, neg_id, severity, summary}` with `severity` in
{HARD_FAIL, SOFT_FAIL, WARNING}. `when` is a one-key expression:
comparisons `gt ge lt le eq ne` take exactly two operands (`METRIC.*`,
`baseline.METRIC.*` or a finite number — JSON booleans are not numbers);
`all`/`any` take a list of expressions; `not` takes one expression. The **whole
tree** is validated before evaluation, so validity never depends on metric
values. A rule with issues is not evaluated.

`RuleHit(rule_id, neg_id, severity, summary)` for every rule whose `when` is true.
`RuleIssue(code, message, rule_id)` codes: `NEG.CONTRADICTION.INVALID_STRUCTURE`,
`UNKNOWN_OPERATOR`, `INVALID_SEVERITY`, `TYPE_MISMATCH`, `UNKNOWN_METRIC`,
`MISSING_BASELINE`, `EVAL_ERROR`.

---

## `event_hysteresis` — two-threshold event windows

```python
hysteresis_windows(t_grid, score, threshold, delta, min_support=2,
                   min_duration=0.0) -> list[EventWindow]
```
FSM per `SPECS/HYSTERESIS_FSM_v1.md`: OUT -> IN at `s >= threshold + delta`,
IN -> OUT at `s <= threshold - delta`. A window is kept if it has at least
`min_support` samples and lasts at least `min_duration`.
`EventWindow(t_start, t_end, t_enter_detected, t_exit_detected, confidence,
reason, support_count)`; `t_exit_detected is None` for a window still open at
the end of the grid. `ValueError` on length mismatch, `delta < 0` (or NaN),
`min_support < 1`, or `min_duration < 0`.

---

## `root_finding` — bracketed root finding

```python
find_root_bracketed(g, bracket, method="brentq", xtol=1e-10, rtol=1e-8,
                    maxiter=100) -> RootResult
```
Methods: `bisect`, `brentq`, `brenth`, `ridder`, `toms748` (SciPy `root_scalar`).
Solver failures never raise: `RootResult(root, converged, iterations, method, message)` with
`converged=False` for an unknown method, a bracket without sign change, or a
solver exception. An exact zero at an endpoint returns that endpoint. Exceptions
raised by `g` itself at the bracket endpoints propagate to the caller.

---

## `freeze_manifest` — integrity gate (ARK-NG-002)

CLI: `python TOOLS/freeze_manifest.py [--manifest PATH] [--regenerate] [--add PATH ...]`.
Without flags it verifies every pinned file (SHA-256 + byte length) and the
coverage policy; exit code non-zero on drift or an unpinned required file
(`NEG.ARCHIVE.UNPINNED_REQUIRED_FILE`). See `docs/FREEZE_COVERAGE_POLICY.md`.
