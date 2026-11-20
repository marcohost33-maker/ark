# Freeze-Manifest Coverage Policy (ARK-NG-002)

The freeze manifest (`artifacts/FREEZE_MANIFEST_v<VERSION>.json`, path from `DEFAULT_MANIFEST`) is the integrity truth
for the freeze line: every listed file is pinned by SHA-256 + byte length, and the CI
gate (`python TOOLS/freeze_manifest.py`) is fail-closed on any drift.

## File classes that MUST be pinned

| Class | Path glob | Rationale |
|---|---|---|
| Integrity / validation tooling | `TOOLS/*.py` | Deterministic decision code; tampering must trip the gate. Includes `freeze_manifest.py` **itself** (self-trust). |
| Test suite | `tests/*.py` | The verification net; silently weakening or adding an unpinned test must trip the gate. |
| Schemas | `SCHEMAS/*.json` | Contract surface for validators. |
| Specs | `SPECS/*.md` | Specs are the contract source (code follows spec). |
| Test vectors | `TESTVECTORS/**` | Golden inputs/oracles. |
| Frozen docs/TOC | `docs/architecture_overview.md`, `docs/FREEZE_COVERAGE_POLICY.md`, `tocs/*`, `README.md`, `artifacts/FREEZE_SUMMARY_*.md` | Released documentation surface. |
| License text | `LICENSE` | Member of every release bundle (Apache-2.0 §4: recipients get a copy); the bundle holds pinned files only, so the license must be pinned. |
| Release notes | `CHANGELOG.md` | Bundled with the release; carries the section-3 classification and every verdict-loosening (`SPECS/VERSIONING_POLICY_v1.md` §3.1), so it must not change unnoticed. |
| Release identity | `VERSION` | Single source of truth for the release version (`SPECS/VERSIONING_POLICY_v1.md`); a silent edit would relabel the frozen state. |
| Line-ending normalization | `.gitattributes` | Cross-platform determinism for byte-level hashes; without it, Windows CRLF normalization can create false or masked drift. |

## Explicit exclusion

- The manifest **cannot pin its own path** (`artifacts/FREEZE_MANIFEST_v<VERSION>.json`):
  writing the digest changes the digest. The verifier treats that exclusion as expected,
  and `add_paths` refuses an attempt to add it.

## How coverage is enforced

`verify_manifest()` now checks two things:

1. every manifest entry matches the working-tree SHA-256 + byte length;
2. every existing file that matches the required coverage policy is present in the manifest.

If a required file class exists but is not pinned, the gate emits
`NEG.ARCHIVE.UNPINNED_REQUIRED_FILE` and exits non-zero in CI. This closes the earlier
"extra required file" gap where adding a new validator/test/spec could silently bypass the
freeze manifest until manually added.

## How to extend coverage

Use the tool, do not hand-edit JSON:

```bash
python TOOLS/freeze_manifest.py --add TOOLS/new_tool.py tests/test_new_tool.py
```

`--add` is fail-closed (non-existent path or self-pin raises) and idempotent, then
re-freezes every entry from the working tree. `--regenerate` also includes all currently
required policy paths, so it can close a coverage gap after a new required file is added.

## Self-trust closure (Issue #9)

Before this policy, `TOOLS/freeze_manifest.py` and the test files were unpinned: the gate
did not verify itself. They are now pinned, so any change to the integrity tool or its
tests forces a deliberate re-freeze and is caught by the gate otherwise.

## Cross-platform determinism

`.gitattributes` enforces `* text=auto eol=lf` so working-tree bytes are LF on every
platform; a Windows checkout would otherwise produce CRLF bytes and false drift.

## Relation to the release bundle (ARK-R8-001)

The release bundle (`TOOLS/release_bundle.py`, `SPECS/ARCHIVE_CONFORMANCE_v1.md`) holds exactly
the files this manifest pins, plus the manifest. Pinning a file therefore ships it; a file that
must reach consumers has to be pinned. The bundle digest pin
`artifacts/RELEASE_BUNDLE_v<VERSION>.sha256` is deliberately **not** pinned here: it records the
digest of an archive that contains this manifest, so it cannot be inside either. After
`--regenerate`, run `python TOOLS/release_bundle.py --pin`.
