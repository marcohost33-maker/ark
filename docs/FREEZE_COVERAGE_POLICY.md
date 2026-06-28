# Freeze-Manifest Coverage Policy (ARK-NG-002)

The freeze manifest (`artifacts/FREEZE_MANIFEST_v1.0.5.json`) is the integrity truth
for the freeze line: every listed file is pinned by SHA-256 + byte length, and the CI
gate (`python TOOLS/freeze_manifest.py`) is fail-closed on any drift.

## File classes that MUST be pinned

| Class | Path glob | Rationale |
|---|---|---|
| Integrity / validation tooling | `TOOLS/*.py` | Deterministic decision code; tampering must trip the gate. Includes `freeze_manifest.py` **itself** (self-trust). |
| Test suite | `tests/*.py` | The verification net; silently weakening a test must trip the gate. |
| Schemas | `SCHEMAS/*.json` | Contract surface for validators. |
| Specs | `SPECS/*.md` | Specs are the contract source (code follows spec). |
| Test vectors | `TESTVECTORS/**` | Golden inputs/oracles. |
| Frozen docs/TOC | `docs/architecture_overview.md`, `docs/FREEZE_COVERAGE_POLICY.md`, `tocs/*`, `README.md`, `artifacts/FREEZE_SUMMARY_*.md` | Released documentation surface. |

## Explicit exclusion

- The manifest **cannot pin its own path** (`artifacts/FREEZE_MANIFEST_v1.0.5.json`):
  writing the digest changes the digest. The verifier treats that exclusion as expected,
  and `add_paths` refuses an attempt to add it.

## How to extend coverage

Use the tool, do not hand-edit JSON:

```bash
python TOOLS/freeze_manifest.py --add TOOLS/new_tool.py tests/test_new_tool.py
```

`--add` is fail-closed (non-existent path or self-pin raises) and idempotent, then
re-freezes every entry from the working tree.

## Self-trust closure (Issue #9)

Before this policy, `TOOLS/freeze_manifest.py` and the test files were unpinned: the gate
did not verify itself. They are now pinned, so any change to the integrity tool or its
tests forces a deliberate re-freeze and is caught by the gate otherwise.

## Cross-platform determinism

`.gitattributes` enforces `* text=auto eol=lf` so working-tree bytes are LF on every
platform; a Windows checkout would otherwise produce CRLF bytes and false drift.
