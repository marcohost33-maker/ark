# Changelog

All notable changes to ARK-Core. Format: [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/);
versions follow [SemVer 2.0.0](https://semver.org/spec/v2.0.0.html) with the verdict-aware bump rules of
`SPECS/VERSIONING_POLICY_v1.md` section 3: a validator's output is its API, so every change that can alter a
verdict for some input is at least MINOR, and every loosening is named below as **verdict-loosening**.

A version is released when the tag `v<VERSION>` exists and the release workflow attested its bundle
(`ARK-Core_v<VERSION>_freeze.tar`); until then its date reads "unreleased".

## [Unreleased]

## [1.1.0] - unreleased

First tagged release. Baseline: the frozen origin archive `ARK-Core_v1.0.5_freeze.zip`
(SHA-256 `3f515f30…`, `SOURCES.md`), imported as commit `b746b6d`; 1.0.5 itself was never tagged.

**Classification (VERSIONING_POLICY section 3): MINOR.** Measured against `b746b6d`: 9 NEG IDs added and
none removed or renamed; CLI flags only added; no schema in `SCHEMAS/` changed; the default exit-code
contract of `validate_run` unchanged (0 = report written, 1 = failure; exit 2 exists only under the new
opt-in `--strict-exit`); no non-downgradable ID became downgradable. Hence not MAJOR. Several
tightenings and exactly one verdict-loosening (below) make it more than PATCH.

### Added
- `validate_run --policy FILE`: explicit policy loading with shape validation before use (#18,
  `docs/POLICY_LOADING.md`).
- `validate_run --strict-exit` (opt-in): the exit code carries the verdict — 0 ACCEPT/ACCEPT_WITH_NOTES,
  1 REJECT, 2 tool error, 3 REVIEW (#37, `SPECS/REPORTING_POLICY_v1.md`, golden vectors `TESTVECTORS/exit/`).
- NEG IDs: `NEG.KERNEL.UNREADABLE`, `NEG.KERNEL.NAME_CASE_MISMATCH`, `NEG.POLICY.UNREADABLE`,
  `NEG.PROV.DUPLICATE_ID`, `NEG.PROV.MISSING_ID`, `NEG.PROV.UNKNOWN_EDGE_TYPE`,
  `NEG.ARCHIVE.UNPINNED_REQUIRED_FILE`, `NEG.ARCHIVE.NONCANONICAL`, `NEG.ARCHIVE.UNSAFE_MEMBER`
  (the `NEG.KERNEL.MISSING_<NAME>` family already existed in 1.0.5; only its matching changed, below).
- Integrity and release tools (stdlib only): `freeze_manifest` (NG-002 freeze gate with a required
  coverage policy), `release_gate` (tag == `v<VERSION>`), `release_sbom` (runtime + build CycloneDX SBOMs
  checked against the hash-locked pins), `release_bundle` (canonical, byte-identical software bundle with a
  closed-world `--verify`), `version_bump` (this release procedure as one command; a failure after its
  first write restores every file it touched or reports `ROLLBACK INCOMPLETE`), and the shared grammars
  `ark_semver` (SemVer 2.0.0) and `ark_json` (I-JSON, RFC 7493).
- Release workflow: build-provenance attestation over bundle, SBOMs and manifest; tag job runs every
  `ci.yml` gate first (#39, #42, #43, #44).
- Single source of truth `VERSION` with a lockstep gate on every PR (#39); `CHANGELOG.md`.

### Changed
Tightenings: inputs that passed before and are refused now.
- Policy levers can no longer downgrade a non-downgradable ID: `waivers`/`known_issues` were a bypass
  (#32); all `NEG.KERNEL.*` and `NEG.POLICY.UNREADABLE` are non-downgradable.
- Kernel files are matched by exact, case-sensitive name on every file system: `kernels/kernel.PLAN.json`
  was counted as the plan on Windows/macOS while its root method went unchecked (#32).
- Kernel `version` must be strict SemVer 2.0.0 with ASCII digits and no trailing newline (#6, #39).
- The root method is read from `kernel.plan.json` `payload.root.METHOD`; an unknown or missing method is
  `NEG.ROOT.UNKNOWN_METHOD` instead of a silent `brentq` fallback (#32).
- `format: date-time` is enforced, closed-world: the set of checked formats no longer depends on which
  optional packages are installed (#18, #43). The schemas use no other format, so no verdict loosened.
- Provenance: `used`/`wasDerivedFrom` edges are reference-checked in PROV-DM direction; unknown edge
  types, nodes without a string id and duplicate ids are refused (were ignored) (#32).
- Contradiction DSL: the whole expression tree is shape-checked (no short-circuit loophole); a JSON
  boolean is not a number (#32).
- Event hysteresis: `delta >= 0`, `min_support >= 1`, `min_duration >= 0` are enforced (#32).
- Severity levers `waived_issue_ids`/`known_issue_ids` must be collections; a string waived every ID it
  contained as a substring (#35, not reachable through the CLI).
- All JSON that decides a verdict is parsed as I-JSON: duplicate member names, `NaN`/`Infinity` and
  surrogate/noncharacter code points are refused (kernel -> `NEG.KERNEL.UNREADABLE`, policy ->
  `NEG.POLICY.UNREADABLE`, manifest -> `NEG.ARCHIVE.MANIFEST_MISMATCH`) (#45).
- Python floor 3.12 (#23); CI tests Windows and macOS with 3.12 and Ubuntu with 3.13.

**Verdict-loosening** (VERSIONING_POLICY section 3.1): inputs that failed before and pass now.
- `validate_run`: a run directory given with a trailing path separator (`--run "...\run\"` on Windows,
  `run/`) produced an empty `run_id` and REJECT (`NEG.REPORT.SCHEMA_INVALID`); the same run is now judged
  like its canonical path, i.e. ACCEPT when it is valid (#34). Affected ID: `NEG.REPORT.SCHEMA_INVALID`
  for that input only.

### Fixed
Crash-to-report fixes that keep the documented verdict (PATCH class).
- Malformed or unmaterialisable kernel JSON (bad syntax, int-digit limit, recursion limit) and an
  unlistable `kernels/` crashed `validate_run`; they are now REJECT reports (#32).
- A policy that cannot be established ended in a traceback with no report, leaving an older ACCEPT report
  in place; the CLI now writes a REJECT report with `NEG.POLICY.UNREADABLE` (#33). An internal crash
  removes a stale report where possible (#37).
- `--out report.json` without a directory part crashed (#33).
- `find_root_bracketed(method=<non-string>)` raised instead of returning an unknown-method result (#35).
- Release path: the SBOM step called an invalid `cyclonedx-py` option and would have failed the first tag
  (#42).

### Security
- Hash-locked dependencies (`--require-hashes --only-binary=:all:`) for CI and release; GitHub Actions
  pinned by commit SHA and audited by zizmor on every PR (#3, #43).
- The release bundle verifier never parses untrusted archives with `tarfile`; members are restricted to
  safe, case-unique, non-device paths (`COM0`-`COM9`, `LPT0`-`LPT9` included) (#44, #45).

## [1.0.5] - 2026-03-11 (origin freeze, never tagged)

The frozen origin archive `ARK-Core_v1.0.5_freeze.zip` (code date 2026-03-11, SHA-256 `3f515f30…`),
imported unchanged as commit `b746b6d` on 2026-06-03 (`SOURCES.md`): 4 JSON Schemas, 14 specs, 6 Python
validators (`validate_run`, `provenance_validate`, `event_hysteresis`, `severity_mapping`, `root_finding`,
`contradiction_rules`), test vectors and a per-file SHA-256 manifest. No tag or attested artifact exists
for 1.0.5; it is the baseline that 1.1.0 is classified against.

[Unreleased]: https://github.com/marcohost33-maker/ark/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/marcohost33-maker/ark/releases/tag/v1.1.0
