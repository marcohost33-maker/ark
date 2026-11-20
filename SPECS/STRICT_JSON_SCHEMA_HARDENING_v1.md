# STRICT_JSON_SCHEMA_HARDENING_v1
Version: 1.0.5
Status: DRAFT

Recommended hardening rules:
- additionalProperties: false on closed objects
- minLength/minItems where sensible
- enum for constrained strings
- format: date-time for timestamps
- use JSON Schema 2020-12 consistently

## Input grammar: I-JSON (normative, 2026-11-20)
Schema rules constrain a parsed document; they cannot see what the parser already
resolved. Every ARK tool that turns JSON bytes into a decision therefore parses with one
grammar, `TOOLS/ark_json.py`: I-JSON (RFC 7493), stdlib only.

Refused, whatever the schema says:
- duplicate object member names, compared after escape processing (`"a"` equals `"\u0061"`)
  (RFC 7493 section 2.3) — parsers disagree on which value wins;
- `NaN`, `Infinity`, `-Infinity` — not JSON (RFC 8259 section 6);
- surrogate and noncharacter code points in member names or string values, escaped or
  not (RFC 7493 section 2.1); an escaped surrogate *pair* is one valid code point.

Not enforced (RFC 7493 SHOULD): numbers beyond IEEE 754 double precision.

A refusal is malformed input and maps to the caller's existing unreadable-input outcome:
`NEG.KERNEL.UNREADABLE` (kernel), `NEG.POLICY.UNREADABLE` (policy, CLI),
`NEG.ARCHIVE.MANIFEST_MISMATCH` (freeze manifest, release bundle), a refused release
(`release_gate`, `release_sbom`). No NEG ID is added. `tests/test_ark_json.py` forbids
`json.load`/`json.loads` anywhere else in `TOOLS/`.
