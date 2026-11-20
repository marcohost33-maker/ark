#!/usr/bin/env python3
"""Release bundle: the software subject of an ARK release (ARK-R8-001, ARK-R8-004).

Contract: SPECS/ARCHIVE_CONFORMANCE_v1.md, section "Release bundle".

Until this tool the release job attested only metadata (SBOMs, freeze manifest,
VERSION): no artifact held the software itself, so no digest named what a consumer
actually runs. The bundle closes that gap without changing the repository layout:

* ``ARK-Core_v<VERSION>_freeze.tar`` holds exactly the files the freeze manifest
  pins, plus the manifest itself, under ``ARK-Core_v<VERSION>_freeze/``. A consumer
  unpacks it and runs ``python TOOLS/validate_run.py`` as documented in docs/API.md.
* The bytes are a pure function of the pinned file bytes and the manifest bytes:
  one canonical ustar encoding (sorted members, fixed metadata, no compression, so
  no zlib version, clock, umask, locale or environment variable can change them).
  Linux, Windows and macOS build the identical file.
* ``artifacts/RELEASE_BUNDLE_v<VERSION>.sha256`` pins the digest in the repository.
  A build refuses to write a bundle whose digest differs from the pin, so the
  digest a release attests was reviewed in a pull request before the tag existed.
* ``--verify`` checks a bundle from its bytes alone (closed world): one canonical
  encoding, safe member paths, member set equal to the manifest, every digest and
  length equal to the manifest, VERSION and manifest naming the same release.

The verifier reads the archive with its own strict parser and never calls
``tarfile`` on untrusted input; a bundle is accepted only if re-encoding its
members reproduces the input byte for byte, which rejects links, directories,
pax/GNU extension headers, altered metadata, reordering and trailing data in one
comparison.

Claim ceiling: verification proves the bundle is internally consistent and
canonical. It does not prove who built it. Authenticity comes from outside the
archive: the committed digest pin, ``--sha256``, and the build-provenance
attestation of the release job (docs/RELEASE_HARDENING.md section 2).

Stdlib only, so it runs under ``python -I -S``.
Exit codes: 0 OK, 1 check failed, 2 usage error.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import freeze_manifest  # noqa: E402  (integrity gate, stdlib only)
from ark_semver import SEMVER_RE  # noqa: E402  (single SemVer grammar, stdlib only)
from release_gate import ReleaseGateError, read_version  # noqa: E402

BLOCK = 512
RECORD = 10240  # 20 blocks: the default record size of POSIX tar, GNU tar and Python tarfile
# 1980-01-01T00:00:00Z. A constant, not SOURCE_DATE_EPOCH: no environment input can
# change the bytes. Not 0, which some extractors report as an implausible timestamp.
MTIME = 315532800
MODE = 0o644
MAX_NAME = 100  # ustar name field; the prefix field is never used, so every name fits here
MAX_BUNDLE_BYTES = 64 * 1024 * 1024

# Files a bundle must hold whatever its manifest lists: release identity and the
# license text (Apache-2.0 section 4 requires giving recipients a copy).
REQUIRED_MEMBERS = ("LICENSE", "VERSION")

NEG_CHECKSUM = "NEG.ARCHIVE.CHECKSUM_FAIL"
NEG_CASING = "NEG.ARCHIVE.CASING_FAIL"
NEG_MANIFEST = "NEG.ARCHIVE.MANIFEST_MISMATCH"
NEG_MISSING = "NEG.ARCHIVE.MISSING_FILE"
NEG_NONCANONICAL = "NEG.ARCHIVE.NONCANONICAL"
NEG_UNSAFE = "NEG.ARCHIVE.UNSAFE_MEMBER"

_SEGMENT_RE = re.compile(r"[A-Za-z0-9._-]+", re.ASCII)
_SHA256_RE = re.compile(r"[0-9a-f]{64}", re.ASCII)
_OCTAL_RE = re.compile(rb"[0-7]+", re.ASCII)
# Names Windows resolves to devices, with or without an extension. COM0/LPT0 are not in the
# Win32 list but OneDrive and SharePoint refuse them, and a consumer may unpack there.
_WINDOWS_DEVICES = frozenset(
    ["con", "prn", "aux", "nul"] + [f"com{i}" for i in range(10)] + [f"lpt{i}" for i in range(10)]
)


class BundleError(ValueError):
    """The bundle cannot be built from this tree."""


def bundle_stem(version: str) -> str:
    return f"ARK-Core_v{version}_freeze"


def bundle_filename(version: str) -> str:
    return bundle_stem(version) + ".tar"


def manifest_relpath(version: str) -> str:
    return f"artifacts/FREEZE_MANIFEST_v{version}.json"


def pin_relpath(version: str) -> str:
    return f"artifacts/RELEASE_BUNDLE_v{version}.sha256"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ------------------------------ canonical encoding ------------------------------ #
def unsafe_path_reason(rel: str) -> Optional[str]:
    """Why ``rel`` is not an acceptable member path, or None.

    Accepted: ``/``-separated segments of ASCII letters, digits, ``.``, ``_``, ``-``.
    Refused: empty, ``.`` and ``..`` segments (traversal), a trailing dot and Windows
    device names (the file would land somewhere else or nowhere on Windows).
    """
    if not isinstance(rel, str) or not rel:
        return "empty path"
    for segment in rel.split("/"):
        if not _SEGMENT_RE.fullmatch(segment):
            return f"segment {segment!a} outside [A-Za-z0-9._-]"
        if segment in (".", "..") or segment.endswith("."):
            return f"segment {segment!a} is a dot segment or ends with a dot"
        if segment.split(".", 1)[0].lower() in _WINDOWS_DEVICES:
            return f"segment {segment!a} is a Windows device name"
    return None


def _header(name: bytes, size: int) -> bytes:
    """One ustar header for a regular file with the fixed bundle metadata."""
    fields = [
        name.ljust(100, b"\0"),
        b"%07o\0" % MODE,
        b"%07o\0" % 0,  # uid
        b"%07o\0" % 0,  # gid
        b"%011o\0" % size,
        b"%011o\0" % MTIME,
        b" " * 8,  # checksum placeholder: summed as spaces
        b"0",  # typeflag: regular file
        b"\0" * 100,  # linkname
        b"ustar\0",
        b"00",
        b"\0" * 32,  # uname
        b"\0" * 32,  # gname
        b"\0" * 8,  # devmajor
        b"\0" * 8,  # devminor
        b"\0" * 155,  # prefix (unused: names are at most 100 bytes)
        b"\0" * 12,
    ]
    block = b"".join(fields)
    assert len(block) == BLOCK
    checksum = b"%06o\0 " % sum(block)
    return block[:148] + checksum + block[156:]


def encode_members(members: Dict[str, bytes]) -> bytes:
    """The one canonical archive for ``members`` (full member name -> content)."""
    out = bytearray()
    for name in sorted(members):
        raw = name.encode("ascii")
        if len(raw) > MAX_NAME:
            raise BundleError(f"member name longer than {MAX_NAME} bytes: {name!a}")
        data = members[name]
        if len(data) >= 8 ** 11:
            raise BundleError(f"member too large for ustar: {name!a}")
        out += _header(raw, len(data))
        out += data
        out += b"\0" * (-len(data) % BLOCK)
    out += b"\0" * (2 * BLOCK)
    out += b"\0" * (-len(out) % RECORD)
    return bytes(out)


def _parse_members(data: bytes) -> Tuple[Optional[List[Tuple[str, bytes]]], Optional[Tuple[str, str]]]:
    """Strict reader: ``(members, None)`` or ``(None, (neg_id, detail))``.

    Only what the canonical encoding can contain is understood. Whether the header
    bytes are canonical is decided afterwards by re-encoding, not here.
    """
    if len(data) % BLOCK:
        return None, (NEG_NONCANONICAL, "archive length is not a multiple of 512")
    members: List[Tuple[str, bytes]] = []
    offset = 0
    while True:
        header = data[offset:offset + BLOCK]
        if len(header) < BLOCK:
            return None, (NEG_NONCANONICAL, "archive ends without an end-of-archive marker")
        if header == b"\0" * BLOCK:
            return members, None
        if header[257:265] != b"ustar\x0000":
            return None, (NEG_NONCANONICAL, f"header at offset {offset} is not POSIX ustar")
        typeflag = header[156:157]
        raw_name = header[0:100].split(b"\0", 1)[0]
        try:
            name = raw_name.decode("ascii")
        except UnicodeDecodeError:
            return None, (NEG_UNSAFE, f"non-ASCII member name at offset {offset}")
        if typeflag != b"0":
            return None, (NEG_UNSAFE, f"member {name!a} is not a regular file (typeflag {typeflag!a})")
        raw_size = header[124:135]
        if not _OCTAL_RE.fullmatch(raw_size):
            return None, (NEG_NONCANONICAL, f"member {name!a} has a malformed size field")
        size = int(raw_size, 8)
        start = offset + BLOCK
        if start + size > len(data):
            return None, (NEG_NONCANONICAL, f"member {name!a} is truncated")
        members.append((name, data[start:start + size]))
        offset = start + size + (-size % BLOCK)


# --------------------------------- verification --------------------------------- #
@dataclass
class BundleReport:
    """Result of :func:`verify_bundle_bytes`. ``negs`` empty == accepted."""

    negs: List[str] = field(default_factory=list)
    details: List[str] = field(default_factory=list)
    version: Optional[str] = None
    files: Dict[str, bytes] = field(default_factory=dict)  # release-relative path -> content

    @property
    def ok(self) -> bool:
        return not self.negs

    def _fail(self, neg_id: str, detail: str) -> None:
        if neg_id not in self.negs:
            self.negs.append(neg_id)
            self.negs.sort()
        self.details.append(f"{neg_id}: {detail}")


def _manifest_entries(raw: bytes, report: BundleReport) -> Optional[Dict[str, Tuple[str, int]]]:
    """``path -> (sha256, bytes)`` from the bundled manifest, or None when malformed."""
    try:
        # I-JSON: a duplicate key would let another reader see a different file list.
        manifest = freeze_manifest.strict_json_loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        report._fail(NEG_MANIFEST, f"bundled manifest is not strict JSON: {exc}")
        return None
    files = manifest.get("files") if isinstance(manifest, dict) else None
    if not isinstance(files, list) or not files:
        report._fail(NEG_MANIFEST, "bundled manifest has no file list")
        return None
    if manifest.get("artifact") != bundle_stem(report.version or ""):
        report._fail(NEG_MANIFEST, f"manifest artifact field is {manifest.get('artifact')!a}")
    entries: Dict[str, Tuple[str, int]] = {}
    for entry in files:
        path = entry.get("path") if isinstance(entry, dict) else None
        digest = entry.get("sha256") if isinstance(entry, dict) else None
        size = entry.get("bytes") if isinstance(entry, dict) else None
        if (
            not isinstance(path, str)
            or not isinstance(digest, str)
            or not _SHA256_RE.fullmatch(digest)
            or type(size) is not int  # bool is an int subclass; a JSON true is not a length
            or size < 0
        ):
            report._fail(NEG_MANIFEST, f"malformed manifest entry for {path!a}")
            return None
        if path in entries:
            report._fail(NEG_MANIFEST, f"manifest lists {path!a} twice")
            return None
        entries[path] = (digest, size)
    return entries


def verify_bundle_bytes(data: bytes, expect_sha256: Optional[str] = None) -> BundleReport:
    """Closed-world check of a release bundle from its bytes alone. Fail-closed."""
    report = BundleReport()
    if expect_sha256 is not None and sha256_hex(data) != expect_sha256.lower():
        report._fail(NEG_CHECKSUM, f"archive sha256 is {sha256_hex(data)}, expected {expect_sha256.lower()}")
    if len(data) > MAX_BUNDLE_BYTES:
        report._fail(NEG_UNSAFE, f"archive larger than {MAX_BUNDLE_BYTES} bytes")
        return report

    parsed, error = _parse_members(data)
    if parsed is None:
        report._fail(*error)
        return report
    if not parsed:
        report._fail(NEG_MISSING, "archive holds no members")
        return report

    # One top-level directory that names a strict SemVer release.
    stem = parsed[0][0].split("/", 1)[0]
    match = re.fullmatch(r"ARK-Core_v(.+)_freeze", stem)
    if not match or not SEMVER_RE.fullmatch(match.group(1)):
        report._fail(NEG_UNSAFE, f"top-level directory {stem!a} does not name a release")
        return report
    report.version = match.group(1)

    members: Dict[str, bytes] = {}
    files: Dict[str, bytes] = {}
    for name, content in parsed:
        top, _, rel = name.partition("/")
        if top != stem:
            report._fail(NEG_UNSAFE, f"member {name!a} is outside {stem}/")
            return report
        reason = unsafe_path_reason(rel)
        if reason:
            report._fail(NEG_UNSAFE, f"member {name!a}: {reason}")
            return report
        if name in members:
            report._fail(NEG_NONCANONICAL, f"member {name!a} appears twice")
            return report
        members[name] = content
        files[rel] = content

    # Names that a case-insensitive filesystem would merge, or a file used as a directory.
    folded: Dict[str, str] = {}
    for rel in sorted(files):
        parts = rel.split("/")
        for depth in range(1, len(parts) + 1):
            key = "/".join(parts[:depth]).lower()
            kind = "file" if depth == len(parts) else "dir"
            spelled = "/".join(parts[:depth])
            seen_kind, _, seen_spelled = folded.setdefault(key, f"{kind}:{spelled}").partition(":")
            if seen_spelled != spelled:
                report._fail(NEG_CASING, f"{spelled!a} and {seen_spelled!a} differ only in case")
            elif seen_kind != kind:
                report._fail(NEG_UNSAFE, f"{spelled!a} is both a file and a directory")
    if not report.ok:
        return report

    try:
        canonical = encode_members(members)
    except BundleError as exc:
        report._fail(NEG_NONCANONICAL, str(exc))
        return report
    if canonical != data:
        report._fail(NEG_NONCANONICAL, "archive bytes differ from the canonical encoding of its members")
        return report

    version = report.version
    if files.get("VERSION") != (version + "\n").encode("ascii"):
        report._fail(NEG_MANIFEST, f"VERSION member does not read {version!a}")
    for required in REQUIRED_MEMBERS:
        if required not in files:
            report._fail(NEG_MISSING, f"required member {required!a} is absent")
    manifest_rel = manifest_relpath(version)
    if manifest_rel not in files:
        report._fail(NEG_MISSING, f"bundle holds no {manifest_rel}")
        return report
    entries = _manifest_entries(files[manifest_rel], report)
    if entries is None:
        return report

    if manifest_rel in entries:
        report._fail(NEG_MANIFEST, "manifest pins its own path")
    for path in sorted(set(files) - set(entries) - {manifest_rel}):
        report._fail(NEG_MANIFEST, f"member {path!a} is not listed in the manifest")
    for path in sorted(entries):
        if path not in files:
            report._fail(NEG_MISSING, f"manifest lists {path!a}, bundle does not hold it")
            continue
        digest, size = entries[path]
        if len(files[path]) != size or sha256_hex(files[path]) != digest:
            report._fail(NEG_CHECKSUM, f"{path!a} does not match its manifest digest/length")
    if report.ok:
        report.files = files
    return report


def read_bundle(path: Path) -> bytes:
    """Read at most ``MAX_BUNDLE_BYTES + 1`` bytes (the verifier refuses anything larger)."""
    with open(path, "rb") as fh:
        return fh.read(MAX_BUNDLE_BYTES + 1)


def extract_bundle(report: BundleReport, dest: Path) -> Path:
    """Write the files of an accepted bundle below ``dest``; returns the release root.

    Only called with a clean report, so every path already passed the member rules.
    Refuses an existing release directory instead of merging into it.
    """
    if not report.ok or not report.files or report.version is None:
        raise BundleError("refusing to extract a bundle that did not verify")
    root = dest / bundle_stem(report.version)
    if root.exists():
        raise BundleError(f"{root} already exists; extract into an empty location")
    for rel in sorted(report.files):
        target = root.joinpath(*rel.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "xb") as fh:
            fh.write(report.files[rel])
    return root


# ------------------------------------ build ------------------------------------- #
def build_bundle(root: Path) -> Tuple[str, bytes]:
    """``(file name, bytes)`` of the bundle for the tree at ``root``. Fail-closed.

    Every file is read once; the bytes that are hashed against the manifest are the
    bytes that are packed, so a file changing between check and pack cannot slip in.
    """
    try:
        version = read_version(root)
    except ReleaseGateError as exc:
        raise BundleError(str(exc)) from exc
    manifest_rel = manifest_relpath(version)
    manifest_path = root.joinpath(*manifest_rel.split("/"))
    if not manifest_path.is_file():
        raise BundleError(f"no freeze manifest for VERSION {version} ({manifest_rel})")
    negs = freeze_manifest.verify_manifest(str(manifest_path), str(root))
    if negs:
        raise BundleError(f"freeze manifest not in sync: {', '.join(negs)}")

    manifest_bytes = manifest_path.read_bytes()
    manifest = freeze_manifest.strict_json_loads(manifest_bytes.decode("utf-8"))
    stem = bundle_stem(version)
    if manifest.get("artifact") != stem:
        raise BundleError(f"freeze manifest artifact field does not name {stem}")

    members: Dict[str, bytes] = {f"{stem}/{manifest_rel}": manifest_bytes}
    for entry in manifest["files"]:
        rel = entry["path"]
        reason = unsafe_path_reason(rel)
        if reason:
            raise BundleError(f"manifest path {rel!a} cannot be bundled: {reason}")
        content = root.joinpath(*rel.split("/")).read_bytes()
        if len(content) != entry["bytes"] or sha256_hex(content) != entry["sha256"]:
            raise BundleError(f"{rel} changed while the bundle was being built")
        members[f"{stem}/{rel}"] = content
    for required in REQUIRED_MEMBERS:
        if f"{stem}/{required}" not in members:
            raise BundleError(f"{required} is not pinned by the freeze manifest, so it cannot be bundled")

    data = encode_members(members)
    # Defense in depth: never emit a bundle this tool's own verifier would refuse.
    report = verify_bundle_bytes(data)
    if not report.ok:
        raise BundleError("built bundle fails its own verification: " + "; ".join(report.details))
    return bundle_filename(version), data


def pin_line(filename: str, data: bytes) -> str:
    """``sha256sum`` format (two spaces = text mode), so ``sha256sum -c`` accepts the pin."""
    return f"{sha256_hex(data)}  {filename}\n"


def read_pin(root: Path, version: str) -> Optional[str]:
    path = root.joinpath(*pin_relpath(version).split("/"))
    try:
        return path.read_text(encoding="ascii")
    except FileNotFoundError:
        return None
    except (OSError, UnicodeDecodeError) as exc:
        raise BundleError(f"digest pin unreadable: {exc}") from exc


# ------------------------------------- CLI -------------------------------------- #
def _say(message: str, *, error: bool = False) -> None:
    # ASCII-safe: a console that cannot encode a detail must not turn a refusal into a crash.
    print(message.encode("ascii", "backslashreplace").decode("ascii"), file=sys.stderr if error else sys.stdout)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument(
        "--out", metavar="DIR", help="build the bundle into DIR; refused unless it matches the pin (or --sha256)"
    )
    action.add_argument("--pin", action="store_true", help="build and (re)write the committed digest pin")
    action.add_argument("--verify", metavar="FILE", help="closed-world check of an existing bundle")
    parser.add_argument(
        "--sha256",
        metavar="HEX",
        help="expected digest of the archive; with --out it replaces the pin file "
        "(rebuilding from an unpacked bundle, which holds no pin)",
    )
    parser.add_argument("--extract", metavar="DIR", help="with --verify: unpack the accepted bundle below DIR")
    args = parser.parse_args(argv)
    if args.extract and not args.verify:
        parser.error("--extract requires --verify")
    if args.sha256 and args.pin:
        parser.error("--sha256 cannot be combined with --pin")
    if args.sha256 and not _SHA256_RE.fullmatch(args.sha256.lower()):
        parser.error("--sha256 expects 64 hexadecimal digits")

    if args.verify:
        try:
            data = read_bundle(Path(args.verify))
        except OSError as exc:
            _say(f"release bundle: cannot read {args.verify}: {exc}", error=True)
            return 2
        report = verify_bundle_bytes(data, args.sha256)
        if not report.ok:
            _say("release bundle: REFUSED", error=True)
            for detail in report.details:
                _say("  " + detail, error=True)
            return 1
        _say(f"release bundle: ok, ARK-Core v{report.version}, {len(report.files)} files, sha256 {sha256_hex(data)}")
        if args.extract:
            try:
                extracted = extract_bundle(report, Path(args.extract))
            except (BundleError, OSError) as exc:
                _say(f"release bundle: extraction failed: {exc}", error=True)
                return 1
            _say(f"release bundle: extracted to {extracted}")
        return 0

    root = Path(args.root)
    try:
        filename, data = build_bundle(root)
        version = read_version(root)
        line = pin_line(filename, data)
        if args.pin:
            pin_path = root.joinpath(*pin_relpath(version).split("/"))
            with open(pin_path, "w", encoding="ascii", newline="\n") as fh:
                fh.write(line)
            _say(f"release bundle: pinned {line.strip()} in {pin_relpath(version)}")
            return 0
        if args.sha256:
            pinned, pin_source = f"{args.sha256.lower()}  {filename}\n", "--sha256"
        else:
            pinned, pin_source = read_pin(root, version), pin_relpath(version)
    except (BundleError, OSError, ValueError) as exc:
        _say(f"release bundle: {exc}", error=True)
        return 1
    if pinned != line:
        _say(
            f"release bundle: digest differs from {pin_source}\n"
            f"  built   : {line.strip()}\n"
            f"  expected: {(pinned or '<no pin file>').strip()}\n"
            "  after an intended change: python TOOLS/freeze_manifest.py --regenerate, "
            "then python TOOLS/release_bundle.py --pin",
            error=True,
        )
        return 1
    out_dir = Path(args.out)
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / filename).write_bytes(data)
    except OSError as exc:
        _say(f"release bundle: cannot write {out_dir / filename}: {exc}", error=True)
        return 1
    _say(f"release bundle: {line.strip()} ({len(data)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
