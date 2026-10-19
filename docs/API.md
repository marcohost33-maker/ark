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
CLI: `python TOOLS/validate_run.py --run DIR [--out FILE] [--policy FILE] [--strict-exit]`
(default output `DIR/reports/gate_report.json`, prints the path). Exit 0 when a
report was written, whatever its status. Exit 1 when the policy cannot be
established (the CLI then writes a REJECT report with `NEG.POLICY.UNREADABLE`
to the output path, #33) or when the report cannot be written. A written report
replaces any older one at that path. If writing fails, the CLI removes the older
report where possible; if it cannot be removed either (e.g. a read-only or locked
file on Windows), the old report stays in place and only exit code 1 signals the
failure -- callers must check the exit code, not just the file.

`--strict-exit` (opt-in, #37) makes the exit code carry the verdict as well:

| Exit | Meaning |
|---|---|
| 0 | `ACCEPT` or `ACCEPT_WITH_NOTES` |
| 1 | `REJECT` |
| 2 | tool error: policy not established (REJECT report with `NEG.POLICY.UNREADABLE` still written), report not writable, or an argparse usage error |
| 3 | `REVIEW` |

2 is argparse's own usage-error code, so every "the tool did not run cleanly"
case shares it and never reads as a verdict (same split as linters such as
Ruff: findings vs. tool failure). A status outside the schema enum maps to 1
(fail-closed). The default stays unchanged so callers that read only the report
keep working; switching the default is a later, separate decision. Note: with
the current checks every NEG ID `validate_run` routes is non-downgradable, so
`REVIEW` (exit 3) is not reachable from its own findings yet.

**Input.** `run_dir/kernels/kernel.{model,plan,events,schema,env}.json`, each an
object with `content_hash`, `version` (SemVer 2.0.0) and `payload`. The plan may
pin the root-finding method as `payload.root.METHOD`; without `payload.root`
the default is `brentq`, a present `root` must carry an allowlisted `METHOD`.
Policy: `policy=None` loads `run_dir/policy.json` if present, else `{}`; an
explicit dict is validated the same way. See `docs/POLICY_LOADING.md`.

**Output.** A report valid against `SCHEMAS/gate_report.schema.json`:
`run_id`, `created_utc`, `status`, `hard_fail`, `soft_fail`, `warnings`,
`known_issues`, `metrics`, `gate_results`.
`run_id` is the last component of `run_dir` under the host path semantics
(`os.path.normpath`): trailing separators are ignored, so `run`, `run/` and, on
Windows, `run\` name the same run (#34). An empty `run_dir` keeps an empty id and
is therefore REJECTed by the report schema.

| NEG ID | When |
|---|---|
| `NEG.KERNEL.MISSING_<NAME>` | a required kernel file is not stored under its EXACT (case-sensitive) name (always HARD, not routable) |
| `NEG.KERNEL.NAME_CASE_MISMATCH` | a stored name differs from a canonical kernel name (the five required ones or the spec-defined `kernel.baseline.json`) only by case (`kernel.PLAN.json`, `kernel.BASELINE.json`, `KERNEL.plan.json`) or two kernel names collide case-insensitively; same verdict on case-sensitive and case-insensitive file systems (always HARD, not routable) |
| `NEG.KERNEL.UNREADABLE` | kernel file is not valid UTF-8 JSON, not an object, or cannot be materialised (integer beyond the int-digit limit, nesting beyond the recursion limit); also when `kernels/` cannot be listed |
| `NEG.KERNEL.MISSING_HASH` / `MISSING_VERSION` / `MISSING_PAYLOAD` | field missing or empty |
| `NEG.KERNEL.INVALID_SEMVER` | `version` is not a SemVer 2.0.0 string |
| `NEG.ROOT.UNKNOWN_METHOD` | `kernel.plan.json` pins a malformed or non-allowlisted root method |
| `NEG.REPORT.SCHEMA_INVALID` | the report fails its own schema (forces `REJECT`) |
| `NEG.POLICY.UNREADABLE` | CLI only: the policy is missing/unreadable/malformed or the run dir cannot be listed (`PolicyError` below); always HARD, not routable |

**Errors.** `PolicyError` (fail-closed) for a missing/unreadable/malformed policy or a run dir that cannot be listed:
unknown keys, override values outside {HARD_FAIL, SOFT_FAIL, WARNING}, non-string
list entries, or any lever that names a non-downgradable id
(`is_non_downgradable`: the NON_DOWNGRADABLE set or any `NEG.KERNEL.*`).

---

## `severity_mapping` — NEG ID -> severity

```python
classify_neg_id(neg_id, policy=None, known_issue_ids=(), waived_issue_ids=(),
                strict_mode=True) -> str
```
Returns one of `HARD_FAIL`, `SOFT_FAIL`, `WARNING`, `KNOWN_ISSUE`, `WAIVED_ISSUE`.

Precedence: non-downgradable ids (`is_non_downgradable(neg_id)`: the
NON_DOWNGRADABLE set or any `NEG.KERNEL.*`) skip every policy lever (spec
`NEG_SEVERITY_MAPPING_v1`) -> waiver -> known issue -> `severity_overrides`
-> built-in HARD / SOFT / WARNING tables -> unknown id (`HARD_FAIL` in strict
mode, `SOFT_FAIL` otherwise). Raises `ValueError` for an override value outside
{HARD_FAIL, SOFT_FAIL, WARNING}, and when `known_issue_ids` / `waived_issue_ids` is
not a list, tuple, set or frozenset (a bare string would match by substring, #35).

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
`converged=False` for an unknown or non-string method (#35), a bracket without sign change, or a
solver exception. An exact zero at an endpoint returns that endpoint. Exceptions
raised by `g` itself at the bracket endpoints propagate to the caller.

---

## `freeze_manifest` — integrity gate (ARK-NG-002)

CLI: `python TOOLS/freeze_manifest.py [--manifest PATH] [--regenerate] [--add PATH ...]`.
Without flags it verifies every pinned file (SHA-256 + byte length) and the
coverage policy; exit code non-zero on drift or an unpinned required file
(`NEG.ARCHIVE.UNPINNED_REQUIRED_FILE`). See `docs/FREEZE_COVERAGE_POLICY.md`.
