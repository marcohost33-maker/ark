# VERSIONING_POLICY_v1
Version: 1.0.5
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
  the version line of `AGENTS.md`, the `**Status:**` line of `README.md`, and the tool/agent
  version claimed by `examples/minimal_run/provenance/prov.json`.
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
1. Classify the changes since the last tag with section 3; set `VERSION`.
2. Update the lockstep copies listed in section 1; `pytest tests/test_version_consistency.py`
   names every copy that is still stale.
3. Generate the new manifest from the previous one (`--regenerate` re-freezes an existing
   manifest and keeps its coverage): copy `artifacts/FREEZE_MANIFEST_v<OLD>.json` to
   `artifacts/FREEZE_MANIFEST_v<VERSION>.json`, set its `artifact` field and `DEFAULT_MANIFEST`,
   then run `python TOOLS/freeze_manifest.py --regenerate`. The previous manifest stays as a
   historical record. Then pin the bundle digest: `python TOOLS/release_bundle.py --pin` writes
   `artifacts/RELEASE_BUNDLE_v<VERSION>.sha256` (re-run it after every re-freeze; CI refuses a
   stale pin).
4. Merge, then push the tag `v<VERSION>`; the release workflow runs the release gate
   (strict SemVer, tag ref, tag == `v<VERSION>`, manifest), the same ruff and compile checks
   as `ci.yml`, the full test suite and the freeze gate, then builds the release bundle (refused
   unless it equals the pinned digest) and attests bundle + SBOMs + manifest.

## 6. Current state (2026-10-21)
No tag exists. Since the frozen origin zip (SHA `3f515f30...`), the hardening waves added NEG IDs
(`NEG.KERNEL.NAME_CASE_MISMATCH`, `NEG.POLICY.UNREADABLE`), tightened and loosened verdicts
(#34: trailing separator no longer REJECTs) and added CLI flags (`--policy`, `--strict-exit`).
#39 tightened the kernel SemVer check: one grammar (`TOOLS/ark_semver.py`), ASCII digits only,
no trailing newline accepted. A kernel VERSION that used non-ASCII digits or ended in a newline
now fails where it passed before (tightening, MINOR).
The release bundle (ARK-R8-001, 2026-11-18) adds a CLI (`TOOLS/release_bundle.py`) and two NEG IDs
(`NEG.ARCHIVE.NONCANONICAL`, `NEG.ARCHIVE.UNSAFE_MEMBER`): additions, MINOR.
Under section 3 the current tree is a MINOR release over the origin: `1.1.0` is due. The bump
itself is an owner decision and not part of this change.
