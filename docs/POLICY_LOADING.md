# Policy loading & schema-format enforcement (`validate_run`)

Hardening introduced by issue #18. Scope: policy ingestion + JSON-Schema
`format` enforcement only — not a rewrite of gate orchestration.

## Explicit policy loading

`validate_run` no longer starts from an internal `policy = {}` with no ingestion
path. Policy is resolved deterministically:

1. `--policy PATH` (CLI) or the `policy=` argument to `validate_run(...)`, else
2. `<run_dir>/policy.json` if it exists, else
3. the empty policy `{}` (default behavior preserved).

### Policy document shape

```json
{
  "severity_overrides": { "NEG.QA.SLOW": "WARNING" },
  "known_issues":       [ "NEG.PROV.MISSING_GENERATION_EDGE" ],
  "waivers":            [ "NEG.EVENT.SHORT_WINDOW" ]
}
```

All keys are optional. The document is validated **before use** and fails closed
(`PolicyError`) on any of:

- not I-JSON (RFC 7493: duplicate member name, `NaN`/`Infinity`, surrogate or noncharacter;
  `SPECS/STRICT_JSON_SCHEMA_HARDENING_v1.md`) — e.g. `{"waivers": ["X"], "waivers": []}`, which
  a first-wins JSON reader would see as a waiver;
- not a JSON object;
- an unknown top-level key;
- `severity_overrides` not an object, or a value outside
  `{HARD_FAIL, SOFT_FAIL, WARNING}`, or an empty key;
- `known_issues` / `waivers` not a list of non-empty strings;
- **any lever (`severity_overrides`, `known_issues`, `waivers`) naming a
  non-downgradable id** — the NON_DOWNGRADABLE set (e.g. `NEG.ROOT.UNKNOWN_METHOD`,
  `NEG.REPORT.SCHEMA_INVALID`) or any `NEG.KERNEL.*` id: such ids must never be
  softened by policy.

The policy does not select the root-finding method; that is pinned per run in
`kernel.plan.json` (`payload.root.METHOD`, see `SPECS/ROOT_FINDING_v1.md`).

## Enforced `format: date-time`

Report self-validation uses `Draft202012Validator` **plus** an explicit
`FormatChecker`. Stock `jsonschema` only enforces `format: date-time` when the
optional `rfc3339-validator` package is installed, so the check is registered here
in-process (stdlib only, deterministic): a `date-time` value must parse as
ISO-8601/RFC-3339 **with an explicit timezone offset**. `created_utc` is therefore
genuinely enforced rather than silently accepted.

The checker is **closed-world** (`FormatChecker(formats=())` + `date-time`, 2026-11-10):
a plain `FormatChecker()` enables whatever optional format packages are importable —
8 formats in a runtime-only install, 20 in the CI env — so any other schema `format`
would be enforced in one environment and ignored in another. Exactly `date-time` is
enforced everywhere; adding a format is a deliberate code change with a test.

## Evidence commands

```sh
# default behavior preserved (no policy file present):
py TOOLS/validate_run.py --run examples/minimal_run
# -> STATUS ACCEPT, exit 0

# malformed policy fails closed:
echo '{"bogus": 1}' > examples/minimal_run/policy.json
py TOOLS/validate_run.py --run examples/minimal_run   # -> REJECT report, NEG.POLICY.UNREADABLE, exit 1
rm examples/minimal_run/policy.json
```

Regression tests: `tests/test_validate_run_hardening.py`.
