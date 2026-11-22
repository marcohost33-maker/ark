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
to the output path, #33), when the report cannot be written, or when the
validator fails internally (e.g. a schema file is missing; traceback on stderr,
no report). Exit 2 on a command-line usage error (argparse). A written report
replaces any older one at that path. When no report is written, the CLI removes
the older report where possible; if it cannot be removed either (e.g. a read-only
or locked file on Windows), the old report stays in place and only the exit code
signals the failure -- callers must check the exit code, not just the file.

`--strict-exit` (opt-in, #37) makes the exit code carry the verdict as well:

| Exit | Meaning |
|---|---|
| 0 | `ACCEPT` or `ACCEPT_WITH_NOTES` |
| 1 | `REJECT` |
| 2 | tool error: policy not established (REJECT report with `NEG.POLICY.UNREADABLE` still written), report not writable, internal failure (no report), or an argparse usage error |
| 3 | `REVIEW` |

2 is argparse's own usage-error code, so every "the tool did not run cleanly"
case shares it and never reads as a verdict (same split as linters such as
Ruff: findings vs. tool failure). A status outside the schema enum maps to 1
(fail-closed). The default stays unchanged so callers that read only the report
keep working; switching the default is a later, separate decision. Note: with
the current checks every NEG ID `validate_run` routes is non-downgradable (each
policy lever on them is refused), so neither `REVIEW` (exit 3) nor
`ACCEPT_WITH_NOTES` is reachable from its own findings yet; both are mapped so
the contract holds once a downgradable check exists.

Limits and caller rules:
- Codes are produced by `main()`. A failure before it runs (interpreter cannot
  start, `jsonschema` not installed -> `ImportError`) exits 1 by Python
  convention, which under `--strict-exit` is indistinguishable from REJECT by the
  code alone. Fail-closed either way (non-zero); a caller that must tell them
  apart deletes the output path first and treats "exit 1 and no report" as a
  tool error.
- Read the code of the validator itself, never of a pipeline: in
  `validate_run ... | tee log` the shell reports `tee`'s status. Use
  `python TOOLS/validate_run.py --run DIR --strict-exit > log 2>&1; rc=$?`
  (or `set -o pipefail` / `${PIPESTATUS[0]}` in bash).
- CI that should fail on REJECT/tool errors but only flag REVIEW:
  `rc=$?; [ "$rc" -eq 0 ] || [ "$rc" -eq 3 ]`.

**Consumer gate contract (normative for gating use).** Without `--strict-exit`
a REJECT report still exits 0. A consumer that gates a promotion, merge or
release on `validate_run` MUST therefore:
1. call it with `--strict-exit` and read the validator's own exit code;
2. promote only on exit 0, never on 1, 2 or 3 (3 = REVIEW needs a human);
3. additionally read the written report and require its `status` to be
   `ACCEPT` or `ACCEPT_WITH_NOTES` (the code and the report must agree).
A consumer that checks only the exit code of a call without `--strict-exit`
fails open on REJECT. Making `--strict-exit` the default is a MAJOR change
under `SPECS/VERSIONING_POLICY_v1.md` section 3 and an owner decision.

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
| `NEG.KERNEL.UNREADABLE` | kernel file is not valid UTF-8 I-JSON (duplicate member name, `NaN`/`Infinity`, surrogate or noncharacter: `SPECS/STRICT_JSON_SCHEMA_HARDENING_v1.md`), not an object, or cannot be materialised (integer beyond the int-digit limit, nesting beyond the recursion limit); also when `kernels/` cannot be listed |
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

---

## `release_bundle` — release bundle, the software subject (ARK-R8-001)

Contract: `SPECS/ARCHIVE_CONFORMANCE_v1.md`, "Release bundle". Stdlib only (`python -I -S`).

```python
build_bundle(root: Path) -> tuple[str, bytes]            # (file name, archive bytes); raises BundleError
verify_bundle_bytes(data: bytes, expect_sha256: str | None = None) -> BundleReport
extract_bundle(report: BundleReport, dest: Path) -> Path  # only for an accepted report
```
`BundleReport`: `negs` (sorted NEG IDs, empty = accepted), `details` (one line per finding),
`version`, `files` (path -> bytes, filled only when accepted), `ok`.

CLI (exactly one of `--out`, `--pin`, `--verify`):

| Command | Effect |
|---|---|
| `python TOOLS/release_bundle.py --out DIR [--sha256 HEX]` | build `DIR/ARK-Core_v<VERSION>_freeze.tar`; writes nothing unless the digest equals `artifacts/RELEASE_BUNDLE_v<VERSION>.sha256` (or `HEX`, for a rebuild from an unpacked bundle, which holds no pin) |
| `python TOOLS/release_bundle.py --pin` | build and (re)write the digest pin |
| `python TOOLS/release_bundle.py --verify FILE [--sha256 HEX] [--extract DIR]` | closed-world check of `FILE`; with `--extract`, unpack an accepted bundle to `DIR/ARK-Core_v<VERSION>_freeze/` (refused if that directory exists) |

Exit 0 OK; 1 check failed (tree not in sync with its manifest, digest differs from the pin,
bundle refused, extraction failed; findings on stderr); 2 usage error or unreadable `FILE`.
The build refuses a tree whose freeze gate is not in sync and never writes a bundle its own
verifier would refuse. The verifier never extracts a refused bundle and does not use `tarfile`.
Acceptance means canonical and internally consistent, not authentic (see the spec's claim ceiling).

## `ark_json` — the one JSON grammar (I-JSON, RFC 7493)

```python
loads(text: str) -> Any          # raises StrictJSONError (a ValueError) beyond I-JSON
load_path(path: str) -> Any      # UTF-8 file -> loads()
```
Refused: duplicate object member names (after escape processing), `NaN`/`Infinity`/`-Infinity`,
surrogate and noncharacter code points in names or strings. Every tool that decides on JSON uses it;
contract: `SPECS/STRICT_JSON_SCHEMA_HARDENING_v1.md` "Input grammar".

## `version_bump` — release procedure (VERSIONING_POLICY §5)

CLI: `python TOOLS/version_bump.py NEW [--root DIR]` and `python TOOLS/version_bump.py V --check`.

```python
version_drift(root: Path, version: str | None = None) -> list[str]  # empty = every lockstep copy names version
is_newer(new: str, old: str) -> bool                                # SemVer 2.0.0 precedence (semver.org §11)
bump(root: Path, new: str) -> list[str]                             # raises BumpError before the first write
```
Refuses, writing nothing, when `NEW` is not strict SemVer, does not outrank `VERSION`, the tree has
lockstep drift, `CHANGELOG.md` lacks a `## [NEW]` section, or a manifest/pin for `NEW` already exists.
Exit codes: 0 bumped (or `--check` clean), 1 refused/failed/drift, 2 usage error.
