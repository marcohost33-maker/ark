# VERSIONING_POLICY_v1
Version: 1.1.0
Status: PROPOSED

Answers ROADMAP "Versionierungs-Politik nach Freeze (SemVer? Schema-Version getrennt von
Tool-Version?)". Normative parts are enforced by `tests/test_version_consistency.py` (every PR)
and by the tag gate in `.github/workflows/release.yml` (every release).

## 1. Release version: SemVer 2.0.0, one source of truth
- The ARK release version lives in exactly one place: the repository file `VERSION`
  (one line, strict SemVer 2.0.0 without a `v` prefix, newline-terminated).
- Release tags are `v<VERSION>`. The release workflow fails when the pushed tag differs from
  `VERSION`, so a release can never attest a manifest of another version.
- The release gate is `TOOLS/release_gate.py`, the first step of the release job. It refuses
  (exit 1, nothing built or attested): a `VERSION` that is not exactly one strict SemVer 2.0.0
  line (`ark_semver.SEMVER_RE`: ASCII digits only, full match, LF-terminated — the same module the kernel check and the PR tests use; stdlib only, ARK-EQ-01/02);
  any ref that is not a tag (a manual dispatch on a branch never attests; the job itself is also
  skipped on non-tag refs); a tag other than `v<VERSION>`; a missing manifest or one whose
  `artifact` field does not read `ARK-Core_v<VERSION>_freeze`. The full test suite then runs on
  the release commit before any artifact is built.
- Lockstep copies (checked against `VERSION` on every PR, never edited independently):
  the `Version:` header of every `SPECS/*.md`, `DEFAULT_MANIFEST` in `TOOLS/freeze_manifest.py`
  (`artifacts/FREEZE_MANIFEST_v<VERSION>.json`, which must exist and whose `artifact` field
  reads `ARK-Core_v<VERSION>_freeze`), `version` in `CITATION.cff`,
  the version line of `AGENTS.md`, the `**Status:**` line of `README.md`, the tool/agent
  version claimed by `examples/minimal_run/provenance/prov.json`, the bundle pin
  `artifacts/RELEASE_BUNDLE_v<VERSION>.sha256` (exists; its digest is checked by every CI build)
  and a `## [<VERSION>]` section in `CHANGELOG.md`. The rules are code in one place,
  `TOOLS/version_bump.py` (`version_drift`), which the PR gate imports.
- Historical records keep the version they describe and are NOT coupled: `SOURCES.md`
  (origin zip `ARK-Core_v1.0.5_freeze.zip`), `artifacts/FREEZE_SUMMARY_v*.md`, `tocs/*`,
  and test-vector input data.
- A freeze is a tag `v<VERSION>` plus the attested release artifacts of that tag, not a label
  on a moving branch. The software subject among them is the release bundle
  `ARK-Core_v<VERSION>_freeze.tar` (`SPECS/ARCHIVE_CONFORMANCE_v1.md`); its digest is pinned in
  `artifacts/RELEASE_BUNDLE_v<VERSION>.sha256` and checked on every PR and in the release job.

## 2. Public surface (what a version promises)
Contracts in `SPECS/`, the JSON Schemas in `SCHEMAS/`, the NEG ID set and each ID's severity
and non-downgradable status, the verdict rules (status derivation), the Python API listed in
`docs/API.md`, and every CLI flag and exit code.

## 3. Bump rules (verdict-aware)
A validator's output is its API: for the same input, the verdict is the contract. Adapted from
the ESLint semantic-versioning policy (more reported problems = minor, fewer = patch), tightened
because ARK verdicts gate releases.

| Bump | Change |
|---|---|
| MAJOR | Removing or renaming a NEG ID, CLI flag or API function; changing the meaning of an exit code or status; a schema change that rejects previously valid documents; making a non-downgradable ID downgradable. |
| MINOR | New NEG ID, check, flag or optional schema property; any change that turns a previous ACCEPT/ACCEPT_WITH_NOTES/REVIEW into a stricter verdict for some input (tightening); any change that turns a stricter verdict into a laxer one (loosening, see 3.1). |
| PATCH | Changes that cannot change any verdict, report field or exit code: crash-to-report fixes that keep the documented verdict, docs, tests, CI, internal refactoring. |

### 3.1 Loosening is never a patch
A change that lets some input pass that failed before is a fail-open risk even when it fixes a
false positive. It is at least MINOR and the release notes name it as `verdict-loosening` with
the affected NEG IDs, so a consumer pinned to `~X.Y` never receives it silently.

## 4. Schemas and reports: separate format version (PROPOSED, phase 2, not implemented)
Following SARIF (`version` = format, `tool.driver.version` = producer) and SchemaVer (bump by
how far a change reaches into existing data), the report format and the producing tool are
versioned separately:
- each schema in `SCHEMAS/` carries its own SemVer in its `$id`
  (e.g. `schema://gate_report/1.0.0`): MAJOR = previously valid documents become invalid,
  MINOR = new optional property, PATCH = description-only;
- reports carry `schema_version` and `tool: {name, version}` so an archived report can be
  re-validated against the exact contract and traced to the exact validator.

Not implemented here: with `additionalProperties: false`, a report carrying the new fields is
rejected by every consumer still holding the current schema (e.g. the USK adapter). Phase 2
therefore needs a consumer migration plan and owner approval.

## 5. Release procedure
1. Classify the changes since the last tag with section 3 and write them as the
   `## [<NEW>]` section of `CHANGELOG.md` (Keep a Changelog), naming every verdict loosening
   (section 3.1) with its NEG IDs. The bump tool refuses to run without this section.
2. `python TOOLS/version_bump.py <NEW>` moves `VERSION` and every lockstep copy of section 1,
   writes `artifacts/FREEZE_MANIFEST_v<NEW>.json` from the previous manifest (which stays as a
   historical record), re-freezes it (`TOOLS/freeze_manifest.py --regenerate`), pins the bundle
   digest (`TOOLS/release_bundle.py --pin`) and removes the previous pin (a tree can build only
   its own version). Preconditions, all checked before the first write: `<NEW>` is strict SemVer
   with higher precedence than `VERSION` (semver.org section 11); no lockstep drift before the
   bump; the changelog section exists; no manifest or pin for `<NEW>` exists yet. A failure
   after the first write restores every touched file (read back) or reports
   `ROLLBACK INCOMPLETE`; this is not crash-atomic, so run the bump in a clean checkout.
   `--check <V>` only reports drift against `<V>`. `tests/test_version_consistency.py` runs the
   whole procedure on a copy of the repository: bump, freeze gate, bundle build against the new
   pin, closed-world verify, release gate for `v<NEW>`, and the version-bound tests.
3. After any later change before the tag: `python TOOLS/freeze_manifest.py --regenerate`, then
   `python TOOLS/release_bundle.py --pin` (CI refuses a stale pin).
4. Merge, then push the tag `v<VERSION>`; the release workflow runs the release gate
   (strict SemVer, tag ref, tag == `v<VERSION>`, manifest), the same ruff and compile checks
   as `ci.yml`, the full test suite and the freeze gate, then builds the release bundle (refused
   unless it equals the pinned digest) and attests bundle + SBOMs + manifest. Set the date of
   the changelog section in the same commit that is tagged, or leave "unreleased" and let the
   tag date stand.

## 6. Current state (2026-11-20)
No tag exists. `VERSION` is `1.1.0` as a release candidate: `CHANGELOG.md` classifies the tree
against the frozen origin zip (SHA `3f515f30...`, commit `b746b6d`) as MINOR, measured on the
public surface (11 NEG IDs added, none removed or renamed; CLI flags only added; no schema
changed; default exit-code contract unchanged), with several tightenings and exactly one
verdict-loosening (#34: a run path with a trailing separator no longer REJECTs). Releasing it
(merging the bump and pushing the tag `v1.1.0`) is the owner's decision.
