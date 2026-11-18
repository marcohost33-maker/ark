"""Release bundle: the attested software subject (ARK-R8-001, ARK-R8-004).

Contract: SPECS/ARCHIVE_CONFORMANCE_v1.md, "Release bundle". Covered here:

* one canonical encoding, pinned by a golden digest and cross-checked against the
  standard library's ``tarfile`` (an independent encoder and reader);
* the repository's bundle equals the committed digest pin on every CI platform;
* a consumer rehearsal: verify, unpack, run the unpacked tools, rebuild the same bytes;
* a negative matrix: every tampered or non-canonical archive is refused with its NEG ID,
  including every single-byte change of a valid bundle.
"""
from __future__ import annotations

import gzip
import importlib
import io
import json
import os
import random
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "TOOLS"))

rb = importlib.import_module("release_bundle")
severity_mapping = importlib.import_module("severity_mapping")

VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
STEM = f"ARK-Core_v{VERSION}_freeze"
MANIFEST_REL = f"artifacts/FREEZE_MANIFEST_v{VERSION}.json"
TOOL = str(ROOT / "TOOLS" / "release_bundle.py")


@pytest.fixture(scope="module")
def bundle() -> bytes:
    name, data = rb.build_bundle(ROOT)
    assert name == f"{STEM}.tar"
    return data


@pytest.fixture(scope="module")
def members(bundle) -> dict[str, bytes]:
    """Release-relative path -> content of the valid bundle."""
    report = rb.verify_bundle_bytes(bundle)
    assert report.ok, report.details
    return dict(report.files)


def encode(files: dict[str, bytes], stem: str = STEM) -> bytes:
    return rb.encode_members({f"{stem}/{rel}": data for rel, data in files.items()})


def with_manifest(tree: dict[str, bytes], /, **manifest_changes) -> dict[str, bytes]:
    """``tree`` plus a manifest that pins exactly it (a self-consistent bundle)."""
    files = {rel: data for rel, data in tree.items() if rel != MANIFEST_REL}
    manifest = {
        "artifact": STEM,
        "files": [
            {"path": rel, "sha256": rb.sha256_hex(data), "bytes": len(data)} for rel, data in sorted(files.items())
        ],
    }
    manifest.update(manifest_changes)
    files[MANIFEST_REL] = json.dumps(manifest).encode("utf-8")
    return files


def negs(data: bytes, **kwargs) -> list[str]:
    return rb.verify_bundle_bytes(data, **kwargs).negs


def run_tool(*args: str, env: dict | None = None, isolated: bool = True):
    flags = ["-I", "-S"] if isolated else []
    return subprocess.run(
        [sys.executable, *flags, TOOL, *args], capture_output=True, text=True, timeout=120, env=env
    )


def copy_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    shutil.copytree(
        ROOT, repo, ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache", ".ruff_cache")
    )
    return repo


# ------------------------------ canonical encoding ------------------------------ #
def test_canonical_encoding_is_pinned_by_a_golden_digest():
    # Fixed input, fixed bytes: the format cannot drift with the platform, the Python
    # version or the environment without this digest changing.
    data = rb.encode_members({"ARK-Core_v0.0.1_freeze/VERSION": b"0.0.1\n"})
    assert len(data) == rb.RECORD
    assert rb.sha256_hex(data) == "8f3802fb4af9b833a6af92d1c4b0e4a3992b7fd6a6d9063f1e5c2cde4b47c89e"


def test_stdlib_tarfile_reads_and_reproduces_the_bundle(bundle, members):
    # Independent reader: names, sizes, contents and metadata as specified.
    # Independent encoder: the same members written by tarfile give the same bytes.
    rebuilt = io.BytesIO()
    seen = {}
    with tarfile.open(fileobj=io.BytesIO(bundle), mode="r:") as src, tarfile.open(
        fileobj=rebuilt, mode="w", format=tarfile.USTAR_FORMAT
    ) as dst:
        for info in src:
            assert info.isreg() and info.mode == 0o644 and info.mtime == rb.MTIME
            assert (info.uid, info.gid, info.uname, info.gname) == (0, 0, "", "")
            content = src.extractfile(info).read()
            seen[info.name] = content
            twin = tarfile.TarInfo(info.name)
            twin.size, twin.mtime, twin.mode = len(content), rb.MTIME, 0o644
            dst.addfile(twin, io.BytesIO(content))
    assert seen == {f"{STEM}/{rel}": data for rel, data in members.items()}
    assert list(seen) == sorted(seen), "members are not sorted"
    assert rebuilt.getvalue() == bundle


def test_tool_does_not_parse_untrusted_archives_with_tarfile():
    source = (ROOT / "TOOLS" / "release_bundle.py").read_text(encoding="utf-8")
    assert "import tarfile" not in source and "from tarfile" not in source


# ------------------------------- this repository -------------------------------- #
def test_repository_bundle_matches_the_committed_pin(bundle):
    # Runs on Linux, Windows and macOS in CI: one pin, so the bytes are identical everywhere.
    pin = (ROOT / "artifacts" / f"RELEASE_BUNDLE_v{VERSION}.sha256").read_bytes()
    assert pin == f"{rb.sha256_hex(bundle)}  {STEM}.tar\n".encode("ascii"), (
        "bundle digest differs from the pin; after an intended change run "
        "`python TOOLS/freeze_manifest.py --regenerate` then `python TOOLS/release_bundle.py --pin`"
    )


def test_bundle_holds_exactly_the_manifest_files_and_the_manifest(members):
    manifest = json.loads((ROOT / MANIFEST_REL).read_text(encoding="utf-8"))
    pinned = {entry["path"] for entry in manifest["files"]}
    assert set(members) == pinned | {MANIFEST_REL}
    for required in ("LICENSE", "VERSION", "TOOLS/validate_run.py", "requirements-runtime.txt"):
        assert required in members
    assert f"artifacts/RELEASE_BUNDLE_v{VERSION}.sha256" not in members, "the pin cannot be inside the bundle"


def test_build_is_deterministic_and_ignores_the_environment(bundle):
    assert rb.build_bundle(ROOT)[1] == bundle
    env = dict(os.environ, SOURCE_DATE_EPOCH="1", TZ="Pacific/Kiritimati", LC_ALL="C", PYTHONHASHSEED="7")
    proc = run_tool("--out", os.devnull + "-unused", "--sha256", "0" * 64, env=env)
    # Refused (wrong expected digest), and the refusal names the digest the build produced.
    assert proc.returncode == 1 and rb.sha256_hex(bundle) in proc.stderr, proc.stderr


def test_cli_build_writes_the_pinned_bundle_stdlib_only(tmp_path, bundle):
    proc = run_tool("--out", str(tmp_path / "dist"))
    assert proc.returncode == 0, proc.stderr
    assert (tmp_path / "dist" / f"{STEM}.tar").read_bytes() == bundle
    assert rb.sha256_hex(bundle) in proc.stdout


# ------------------------------ consumer rehearsal ------------------------------ #
def test_consumer_can_verify_unpack_run_and_rebuild(tmp_path, bundle):
    archive = tmp_path / f"{STEM}.tar"
    archive.write_bytes(bundle)
    digest = rb.sha256_hex(bundle)
    proc = run_tool("--verify", str(archive), "--sha256", digest, "--extract", str(tmp_path / "unpacked"))
    assert proc.returncode == 0, proc.stderr
    release = tmp_path / "unpacked" / STEM

    def unpacked(script: str, *args: str, isolated: bool = False):
        flags = ["-I", "-S"] if isolated else []
        return subprocess.run(
            [sys.executable, *flags, str(release / script), *args], capture_output=True, text=True, timeout=120
        )

    # The unpacked tree passes its own integrity gate ...
    gate = unpacked("TOOLS/freeze_manifest.py", isolated=True)
    assert gate.returncode == 0, gate.stderr
    # ... its validator gives the documented verdict for the shipped example ...
    report_path = tmp_path / "gate_report.json"
    run = unpacked(
        "TOOLS/validate_run.py", "--run", str(release / "examples" / "minimal_run"), "--out", str(report_path)
    )
    assert run.returncode == 0, run.stderr
    expected = json.loads((release / "examples/minimal_run/expected/gate_report.json").read_text(encoding="utf-8"))
    assert json.loads(report_path.read_text(encoding="utf-8"))["status"] == expected["status"]
    # ... and it rebuilds the bundle it came from, byte for byte.
    rebuild = unpacked("TOOLS/release_bundle.py", "--out", str(tmp_path / "rebuilt"), "--sha256", digest, isolated=True)
    assert rebuild.returncode == 0, rebuild.stderr
    assert (tmp_path / "rebuilt" / f"{STEM}.tar").read_bytes() == bundle


def test_extract_refuses_an_existing_release_directory(tmp_path, bundle):
    report = rb.verify_bundle_bytes(bundle)
    rb.extract_bundle(report, tmp_path)
    with pytest.raises(rb.BundleError):
        rb.extract_bundle(report, tmp_path)


def test_extract_refuses_a_bundle_that_did_not_verify(tmp_path, members):
    report = rb.verify_bundle_bytes(encode({**members, "TOOLS/extra.py": b"x"}))
    assert not report.ok and report.files == {}
    with pytest.raises(rb.BundleError):
        rb.extract_bundle(report, tmp_path)
    assert not any(tmp_path.iterdir())


# -------------------------------- negative matrix -------------------------------- #
def test_expected_digest_mismatch_is_refused(bundle):
    assert negs(bundle, expect_sha256="0" * 64) == [rb.NEG_CHECKSUM]
    assert negs(bundle, expect_sha256=rb.sha256_hex(bundle).upper()) == []


def test_changed_file_content_is_refused(members):
    tampered = dict(members)
    tampered["TOOLS/validate_run.py"] += b"\n# injected\n"
    assert negs(encode(tampered)) == [rb.NEG_CHECKSUM]
    # Same length, different bytes: the length check alone would not catch it.
    swapped = dict(members)
    swapped["VERSION"], swapped["LICENSE"] = members["VERSION"], members["LICENSE"][:-1] + b"X"
    assert negs(encode(swapped)) == [rb.NEG_CHECKSUM]


def test_member_missing_from_the_bundle_is_refused(members):
    without = {rel: data for rel, data in members.items() if rel != "TOOLS/severity_mapping.py"}
    assert negs(encode(without)) == [rb.NEG_MISSING]


def test_member_not_listed_in_the_manifest_is_refused(members):
    assert negs(encode({**members, "TOOLS/sitecustomize.py": b"import os\n"})) == [rb.NEG_MANIFEST]


@pytest.mark.parametrize("required", ["LICENSE", "VERSION"])
def test_self_consistent_bundle_without_a_required_member_is_refused(members, required):
    files = with_manifest({rel: data for rel, data in members.items() if rel != required})
    assert rb.NEG_MISSING in negs(encode(files))


def test_bundle_without_manifest_is_refused(members):
    without = {rel: data for rel, data in members.items() if rel != MANIFEST_REL}
    assert negs(encode(without)) == [rb.NEG_MISSING]


@pytest.mark.parametrize(
    "change",
    [
        {"artifact": "ARK-Core_v9.9.9_freeze"},
        {"files": []},
        {"files": "TOOLS"},
        {"files": [{"path": "VERSION", "sha256": "0" * 64, "bytes": True}]},
        {"files": [{"path": "VERSION", "sha256": "ABC", "bytes": 6}]},
        {"files": [{"path": 7, "sha256": "0" * 64, "bytes": 6}]},
        {"files": ["VERSION"]},
    ],
)
def test_malformed_or_foreign_manifest_is_refused(members, change):
    assert rb.NEG_MANIFEST in negs(encode(with_manifest(members, **change)))


def test_manifest_edge_cases_are_refused(members):
    files = with_manifest(members)
    manifest = json.loads(files[MANIFEST_REL])
    entry = manifest["files"][0]

    duplicated = dict(files)
    duplicated[MANIFEST_REL] = json.dumps({**manifest, "files": manifest["files"] + [entry]}).encode()
    assert negs(encode(duplicated)) == [rb.NEG_MANIFEST]

    self_pin = dict(files)
    self_pin[MANIFEST_REL] = json.dumps(
        {**manifest, "files": manifest["files"] + [{"path": MANIFEST_REL, "sha256": "0" * 64, "bytes": 1}]}
    ).encode()
    assert rb.NEG_MANIFEST in negs(encode(self_pin))

    for raw in (b"not json", b"\xff\xfe", b"[]", b"[" * 100000):
        assert negs(encode({**files, MANIFEST_REL: raw})) == [rb.NEG_MANIFEST]


def test_version_file_must_match_the_release_directory(members):
    files = with_manifest({**members, "VERSION": b"9.9.9\n"})
    assert negs(encode(files)) == [rb.NEG_MANIFEST]


@pytest.mark.parametrize(
    "name",
    [
        f"{STEM}/../evil.py",
        f"{STEM}/./TOOLS/x.py",
        f"{STEM}//x.py",
        f"{STEM}/TOOLS/",
        f"{STEM}/TOOLS\\x.py",
        f"{STEM}/TOOLS/x y.py",
        f"{STEM}/TOOLS/x.py.",
        f"{STEM}/NUL",
        f"{STEM}/docs/con.md",
        f"{STEM}/TOOLS/COM1.py",
        "/etc/passwd",
        "other-dir/VERSION",
        STEM,
    ],
)
def test_unsafe_member_path_is_refused(members, name):
    archive = rb.encode_members({**{f"{STEM}/{rel}": data for rel, data in members.items()}, name: b"x"})
    assert negs(archive) == [rb.NEG_UNSAFE]


@pytest.mark.parametrize("stem", ["ARK-Core_v1.0_freeze", "ARK-Core_v01.0.5_freeze", "ark", "ARK-Core_v1.0.5٠_freeze"])
def test_top_level_directory_must_name_a_strict_semver_release(stem):
    try:
        archive = rb.encode_members({f"{stem}/VERSION": b"1.0.5\n"})
    except UnicodeEncodeError:
        return  # a non-ASCII name cannot even be encoded
    assert negs(archive) == [rb.NEG_UNSAFE]


def test_case_collision_and_file_directory_conflict_are_refused(members):
    assert negs(encode({**members, "TOOLS/Validate_Run.py": b"x"})) == [rb.NEG_CASING]
    assert negs(encode({**members, "tools/other.py": b"x"})) == [rb.NEG_CASING]
    assert negs(encode({**members, "VERSION/x": b"x"})) == [rb.NEG_UNSAFE]


def _tarfile_archive(members: dict[str, bytes], *, mutate=None, extra=None, fmt=tarfile.USTAR_FORMAT) -> bytes:
    """The bundle's members written by tarfile, optionally with altered metadata."""
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=fmt) as tar:
        for rel in sorted(members):
            info = tarfile.TarInfo(f"{STEM}/{rel}")
            info.size, info.mtime, info.mode = len(members[rel]), rb.MTIME, 0o644
            if mutate and rel == "VERSION":
                mutate(info)
            tar.addfile(info, io.BytesIO(members[rel]))
        if extra:
            tar.addfile(extra)
    return out.getvalue()


def _set(**attrs):
    def mutate(info: tarfile.TarInfo) -> None:
        for key, value in attrs.items():
            setattr(info, key, value)
    return mutate


@pytest.mark.parametrize(
    "attrs",
    [{"mtime": 0}, {"mtime": rb.MTIME + 1}, {"mode": 0o755}, {"mode": 0o4644}, {"uid": 1000}, {"gid": 1000},
     {"uname": "root"}, {"gname": "wheel"}],
)
def test_altered_metadata_is_refused(members, attrs):
    assert _tarfile_archive(members) == encode(members)  # the helper itself is canonical
    assert negs(_tarfile_archive(members, mutate=_set(**attrs))) == [rb.NEG_NONCANONICAL]


def _special(name: str, kind: bytes, linkname: str = "") -> tarfile.TarInfo:
    info = tarfile.TarInfo(f"{STEM}/{name}")
    info.type, info.linkname, info.mtime, info.mode = kind, linkname, rb.MTIME, 0o644
    return info


@pytest.mark.parametrize(
    "extra",
    [
        _special("zz-link", tarfile.SYMTYPE, "/etc/passwd"),
        _special("zz-hard", tarfile.LNKTYPE, f"{STEM}/VERSION"),
        _special("zz-dir", tarfile.DIRTYPE),
        _special("zz-fifo", tarfile.FIFOTYPE),
        _special("zz-dev", tarfile.CHRTYPE),
    ],
    ids=["symlink", "hardlink", "directory", "fifo", "device"],
)
def test_non_regular_member_is_refused(members, extra):
    assert negs(_tarfile_archive(members, extra=extra)) == [rb.NEG_UNSAFE]


def test_other_tar_dialects_and_wrappers_are_refused(bundle, members):
    assert negs(_tarfile_archive(members, fmt=tarfile.GNU_FORMAT)) == [rb.NEG_NONCANONICAL]
    # pax: a global/extended header is a non-regular member.
    pax = io.BytesIO()
    with tarfile.open(fileobj=pax, mode="w", format=tarfile.PAX_FORMAT, pax_headers={"comment": "x"}) as tar:
        info = tarfile.TarInfo(f"{STEM}/VERSION")
        info.size = len(members["VERSION"])
        tar.addfile(info, io.BytesIO(members["VERSION"]))
    assert negs(pax.getvalue()) == [rb.NEG_UNSAFE]
    assert negs(gzip.compress(bundle, mtime=0)) == [rb.NEG_NONCANONICAL]
    assert negs(b"") == [rb.NEG_NONCANONICAL]  # not even an end-of-archive marker
    assert negs(b"\0" * rb.RECORD) == [rb.NEG_MISSING]
    assert negs(b"PK\x03\x04" + b"\0" * 508) == [rb.NEG_NONCANONICAL]


def test_reordered_duplicated_truncated_or_padded_archive_is_refused(bundle, members):
    names = sorted(f"{STEM}/{rel}" for rel in members)
    first_len = rb.BLOCK + len(members[names[0].split("/", 1)[1]])
    first_len += -first_len % rb.BLOCK
    first, rest = bundle[:first_len], bundle[first_len:]
    second_len = rb.BLOCK + len(members[names[1].split("/", 1)[1]])
    second_len += -second_len % rb.BLOCK
    swapped = rest[:second_len] + first + rest[second_len:]
    assert len(swapped) == len(bundle)
    assert negs(swapped) == [rb.NEG_NONCANONICAL]
    assert negs(first + bundle) == [rb.NEG_NONCANONICAL]  # first member twice
    assert negs(bundle + b"\0" * rb.RECORD) == [rb.NEG_NONCANONICAL]  # extra padding
    assert negs(bundle + b"trailing data, not a block") == [rb.NEG_NONCANONICAL]
    assert negs(bundle[: len(bundle) - rb.RECORD]) != []
    assert negs(bundle[:first_len]) == [rb.NEG_NONCANONICAL]  # no end-of-archive marker
    assert negs(bundle[: first_len - rb.BLOCK]) != []
    # Data hidden after the end-of-archive marker, inside the record padding.
    hidden = bytearray(bundle)
    hidden[-1] = 1
    assert negs(bytes(hidden)) == [rb.NEG_NONCANONICAL]


def test_every_single_byte_change_of_a_valid_bundle_is_refused(bundle):
    # Deterministic property: the whole first header, plus 400 seeded positions across
    # the archive (headers, contents, block padding, end marker). No change may verify.
    rng = random.Random(0xA4C0)
    positions = list(range(rb.BLOCK)) + [rng.randrange(len(bundle)) for _ in range(400)]
    accepted = []
    for pos in positions:
        mutated = bytearray(bundle)
        mutated[pos] ^= 1 << rng.randrange(8)
        if rb.verify_bundle_bytes(bytes(mutated)).ok:
            accepted.append(pos)
    assert not accepted, f"single-byte changes accepted at offsets {accepted}"


def test_oversized_archive_is_refused_without_parsing(monkeypatch, bundle):
    monkeypatch.setattr(rb, "MAX_BUNDLE_BYTES", len(bundle) - 1)
    assert negs(bundle) == [rb.NEG_UNSAFE]


def test_member_name_longer_than_the_ustar_name_field_cannot_be_built():
    with pytest.raises(rb.BundleError):
        rb.encode_members({f"{STEM}/" + "a" * 100: b""})


def test_bundle_neg_ids_are_hard_failures_in_every_mode():
    for neg_id in (rb.NEG_NONCANONICAL, rb.NEG_UNSAFE, rb.NEG_CHECKSUM, rb.NEG_CASING, rb.NEG_MANIFEST, rb.NEG_MISSING):
        assert severity_mapping.classify_neg_id(neg_id, strict_mode=False) == "HARD_FAIL", neg_id


# ------------------------------- build refusals ---------------------------------- #
def test_build_refuses_a_tree_that_drifted_from_its_manifest(tmp_path):
    repo = copy_repo(tmp_path)
    with open(repo / "TOOLS" / "validate_run.py", "ab") as fh:
        fh.write(b"\n# drift\n")
    with pytest.raises(rb.BundleError, match="not in sync"):
        rb.build_bundle(repo)
    proc = run_tool("--root", str(repo), "--out", str(tmp_path / "dist"))
    assert proc.returncode == 1 and not (tmp_path / "dist").exists(), proc.stderr


def test_build_refuses_an_unpinned_required_file(tmp_path):
    repo = copy_repo(tmp_path)
    (repo / "TOOLS" / "new_tool.py").write_text("x = 1\n", encoding="utf-8")
    with pytest.raises(rb.BundleError, match="UNPINNED_REQUIRED_FILE"):
        rb.build_bundle(repo)


def test_pin_procedure_after_an_intended_change(tmp_path):
    # SPECS/VERSIONING_POLICY_v1.md section 5: change -> re-freeze -> re-pin -> build.
    repo = copy_repo(tmp_path)
    dist = tmp_path / "dist"
    with open(repo / "docs" / "API.md", "ab") as fh:
        fh.write(b"\nintended change\n")

    def step(script: str, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-I", "-S", str(repo / "TOOLS" / script), *args],
            capture_output=True, text=True, timeout=120,
        )

    assert step("freeze_manifest.py", "--regenerate").returncode == 0
    stale = step("release_bundle.py", "--out", str(dist))
    assert stale.returncode == 1 and "digest differs" in stale.stderr and not dist.exists(), stale.stderr
    assert step("release_bundle.py", "--pin").returncode == 0
    fresh = step("release_bundle.py", "--out", str(dist))
    assert fresh.returncode == 0, fresh.stderr
    pin = (repo / "artifacts" / f"RELEASE_BUNDLE_v{VERSION}.sha256").read_text(encoding="ascii")
    assert pin == f"{rb.sha256_hex((dist / f'{STEM}.tar').read_bytes())}  {STEM}.tar\n"


def test_build_without_a_pin_file_is_refused(tmp_path):
    repo = copy_repo(tmp_path)
    (repo / "artifacts" / f"RELEASE_BUNDLE_v{VERSION}.sha256").unlink()
    proc = run_tool("--root", str(repo), "--out", str(tmp_path / "dist"))
    assert proc.returncode == 1 and "<no pin file>" in proc.stderr and not (tmp_path / "dist").exists()


@pytest.mark.parametrize(
    "argv",
    [[], ["--out", "d", "--pin"], ["--extract", "d", "--pin"], ["--pin", "--sha256", "0" * 64],
     ["--verify", "x.tar", "--sha256", "xyz"]],
)
def test_usage_errors_exit_2(argv):
    assert run_tool(*argv).returncode == 2


def test_verify_cli_reports_refusal_and_unreadable_file(tmp_path, members):
    bad = tmp_path / "bad.tar"
    bad.write_bytes(encode({**members, "TOOLS/extra.py": b"x"}))
    proc = run_tool("--verify", str(bad), "--extract", str(tmp_path / "out"))
    assert proc.returncode == 1 and rb.NEG_MANIFEST in proc.stderr and not (tmp_path / "out").exists()
    assert run_tool("--verify", str(tmp_path / "absent.tar")).returncode == 2


# ------------------------------- workflow wiring --------------------------------- #
def _workflow(name: str) -> str:
    return (ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")


def test_release_job_builds_the_bundle_before_it_attests():
    release = _workflow("release.yml")
    build = release.index("python TOOLS/release_bundle.py --out dist\n")
    attest = release.index("actions/attest-build-provenance@")
    assert release.index("run: python TOOLS/freeze_manifest.py\n") < build < attest
    assert 'subject-path: "dist/*"' in release[attest:], "the bundle in dist/ must be an attested subject"


def test_every_ci_platform_builds_the_pinned_bundle():
    ci = _workflow("ci.yml")
    gate, portability = ci.split("\n  portability:\n", 1)
    for job, text in (("gate", gate), ("portability", portability)):
        assert "python TOOLS/release_bundle.py --out " in text, f"ci.yml job {job} does not build the bundle"
