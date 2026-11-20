# ARCHIVE_CONFORMANCE_v1
Version: 1.0.5
Status: DRAFT

Required checks:
- schema
- schematron
- referenced files exist
- casing
- checksums
- manifest matching

## Release bundle (ARK-R8-001, ARK-R8-004)
The software subject of a release is one archive, `ARK-Core_v<VERSION>_freeze.tar`.
Reference implementation: `TOOLS/release_bundle.py`; tests: `tests/test_release_bundle.py`.

### Content (closed world)
- Members are exactly the files pinned by `artifacts/FREEZE_MANIFEST_v<VERSION>.json` plus that
  manifest, each stored as `ARK-Core_v<VERSION>_freeze/<repository path>`. Nothing else.
- `VERSION` and `LICENSE` are always members. `VERSION` reads `<VERSION>` and the manifest's
  `artifact` field reads `ARK-Core_v<VERSION>_freeze`; `<VERSION>` is strict SemVer 2.0.0.
- A bundle is built only from a tree whose freeze gate is in sync, and the bytes checked against
  the manifest are the bytes packed.

### Encoding (one canonical form)
The archive bytes are a function of the member paths and contents only:
- POSIX ustar, uncompressed; regular files only (no directory, link, device, pax or GNU
  extension entries); members sorted by name (code point order), each name at most 100 bytes
  (the ustar prefix field is unused);
- every header carries mode `0644`, uid/gid `0`, empty user and group names and mtime
  `315532800` (1980-01-01T00:00:00Z);
- two zero blocks end the archive, padded with zeros to a multiple of 10240 bytes.

No clock, environment variable, umask, locale, compression library or platform enters the bytes;
every supported platform builds the identical file.

### Member paths
`/`-separated segments of `[A-Za-z0-9._-]`. Refused: empty, `.` and `..` segments, a segment
ending in `.`, Windows device names (`CON`, `PRN`, `AUX`, `NUL`, `COM0`-`COM9`, `LPT0`-`LPT9`,
with or without extension, any case; `COM0`/`LPT0` because OneDrive and SharePoint refuse them),
two paths that differ only in case, and a path that is both a file and a directory.

### Verification (from the archive bytes alone, fail-closed)
A verifier accepts a bundle only if all of the following hold; otherwise it reports the NEG ID
and extracts nothing:

| Check | NEG ID |
|---|---|
| archive digest equals the expected digest, when one is given | `NEG.ARCHIVE.CHECKSUM_FAIL` |
| size within the limit (64 MiB); regular-file members only; safe member paths under one release directory | `NEG.ARCHIVE.UNSAFE_MEMBER` |
| no two paths differ only in case | `NEG.ARCHIVE.CASING_FAIL` |
| re-encoding the members reproduces the archive byte for byte | `NEG.ARCHIVE.NONCANONICAL` |
| manifest present, `VERSION` and `LICENSE` present, every manifest entry present | `NEG.ARCHIVE.MISSING_FILE` |
| manifest well-formed (strict JSON, see below), names this release, does not pin itself; `VERSION` matches; no member outside the manifest | `NEG.ARCHIVE.MANIFEST_MISMATCH` |
| every member matches its manifest SHA-256 and byte length | `NEG.ARCHIVE.CHECKSUM_FAIL` |

All of these are HARD_FAIL.

**Strict JSON (I-JSON, RFC 7493).** The manifest, bundled or in the repository, is parsed with
the ARK input grammar (`SPECS/STRICT_JSON_SCHEMA_HARDENING_v1.md`, `TOOLS/ark_json.py`):
duplicate object keys, the non-finite constants `NaN`, `Infinity`, `-Infinity` and surrogate or
noncharacter code points are refused. JSON
parsers disagree on duplicate keys (Python keeps the last, others the first), so a manifest with
one would name different file lists to different readers; it is a
`NEG.ARCHIVE.MANIFEST_MISMATCH`, not a document to be resolved. The freeze gate
(`TOOLS/freeze_manifest.py`) applies the same rule and also refuses a manifest that is not a JSON
object.

### Digest pin
`artifacts/RELEASE_BUNDLE_v<VERSION>.sha256` (`sha256sum` format) records the bundle digest in
the repository. It is not a member of the bundle. A build that does not reproduce the pinned
digest writes nothing, so the digest a release attests was part of the reviewed source.

### Claim ceiling
Verification shows a bundle is canonical and internally consistent. It does not show who
produced it: a self-consistent bundle with different content verifies too. Authenticity comes
from outside the archive: the digest pin of the tagged commit, an expected digest, and the
release job's build-provenance attestation over the bundle.
