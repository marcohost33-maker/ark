"""Version single source of truth (SPECS/VERSIONING_POLICY_v1.md).

``VERSION`` is the only place the ARK release version is set. Every lockstep copy
must match it on every PR, so a bump that misses one fails here and names it, and
the release workflow can verify ``tag == v<VERSION>``. The bump procedure of the
spec (section 5) is exercised end to end on a copy of the repository.
"""
from __future__ import annotations

import importlib
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "TOOLS"))

release_gate = importlib.import_module("release_gate")


version_bump = importlib.import_module("version_bump")


def read_version(root: Path) -> str:
    # One rule for PRs and releases: the release workflow runs TOOLS/release_gate.py,
    # which reads VERSION with exactly this function (raises a ValueError subclass).
    return release_gate.read_version(root)


# The lockstep rules live in TOOLS/version_bump.py, so the bump tool and this PR gate
# cannot disagree about what a consistent tree is.
version_drift = version_bump.version_drift


def test_version_file_is_strict_semver():
    assert read_version(ROOT)


@pytest.mark.parametrize("raw", ["1.0.5", "v1.0.5\n", "1.0.5 \n", "1.0.5\n\n", "1.0\n", "01.0.5\n"])
def test_malformed_version_file_is_rejected(tmp_path, raw):
    (tmp_path / "VERSION").write_text(raw, encoding="utf-8")
    with pytest.raises(ValueError):
        read_version(tmp_path)


def test_all_lockstep_copies_match_version():
    assert version_drift(ROOT) == []


def test_release_workflow_derives_version_and_gates_the_tag():
    wf = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    # No hard-coded manifest version: the release must follow VERSION.
    assert not re.search(r"FREEZE_MANIFEST_v\d", wf), "release.yml hard-codes a manifest version"
    # The gate is the Python tool (strict SemVer, tag-only), not a shell character class.
    assert "run: python TOOLS/release_gate.py\n" in wf
    assert "case " not in wf, "shell case pattern is back in release.yml"
    # Template injection in run scripts is audited by zizmor (required CI check).


# ----------------------- bump procedure, end to end ------------------------ #
def _run(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, *args], capture_output=True, text=True, timeout=300, cwd=cwd)


def _copy_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    shutil.copytree(
        ROOT, repo, ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache", ".ruff_cache")
    )
    return repo


def _next(old: str) -> str:
    major, minor, _ = (int(x) for x in old.split("+")[0].split("-")[0].split("."))
    return f"{major}.{minor + 1}.0"


def _add_release_notes(repo: Path, new: str) -> None:
    path = repo / "CHANGELOG.md"
    text = path.read_text(encoding="utf-8")
    path.write_text(text.replace("## [Unreleased]\n", f"## [Unreleased]\n\n## [{new}] - unreleased\n\n### Changed\n- test bump\n", 1),
                    encoding="utf-8", newline="\n")


def _snapshot(repo: Path) -> dict[str, bytes]:
    # Byte-compiled caches are written by the interpreter on import, not by the tool.
    return {
        str(p.relative_to(repo)): p.read_bytes()
        for p in sorted(repo.rglob("*"))
        if p.is_file() and "__pycache__" not in p.parts
    }


def test_bump_procedure_end_to_end(tmp_path):
    """VERSIONING_POLICY section 5 on a copy: bump, freeze gate, bundle, verify, version-bound tests."""
    repo = _copy_repo(tmp_path)
    old = read_version(repo)
    new = _next(old)

    # Only VERSION changed -> the gate names the stale copies (incl. manifest, pin, changelog).
    (repo / "VERSION").write_text(new + "\n", encoding="utf-8", newline="\n")
    stale = version_drift(repo)
    for needle in ("SPECS/", "DEFAULT_MANIFEST", "RELEASE_BUNDLE", "CHANGELOG.md", "CITATION.cff"):
        assert any(needle in s for s in stale), (needle, stale)
    (repo / "VERSION").write_text(old + "\n", encoding="utf-8", newline="\n")
    assert version_drift(repo) == []

    _add_release_notes(repo, new)
    proc = _run(str(repo / "TOOLS" / "version_bump.py"), new, "--root", str(repo))
    assert proc.returncode == 0, proc.stderr
    assert read_version(repo) == new
    assert version_drift(repo) == []
    assert not (repo / "artifacts" / f"RELEASE_BUNDLE_v{old}.sha256").exists()
    assert (repo / "artifacts" / f"FREEZE_MANIFEST_v{old}.json").exists()  # historical record stays

    # The release job's own commands on the bumped tree.
    assert _run("-I", str(repo / "TOOLS" / "freeze_manifest.py"), cwd=repo).returncode == 0
    out = tmp_path / "dist"
    build = _run("-I", str(repo / "TOOLS" / "release_bundle.py"), "--root", str(repo), "--out", str(out))
    assert build.returncode == 0, build.stderr
    bundle = out / f"ARK-Core_v{new}_freeze.tar"
    pinned = (repo / "artifacts" / f"RELEASE_BUNDLE_v{new}.sha256").read_text(encoding="ascii").split()[0]
    verify = _run("-I", str(repo / "TOOLS" / "release_bundle.py"), "--verify", str(bundle), "--sha256", pinned)
    assert verify.returncode == 0, verify.stderr
    gate_env_ok = _run(
        "-c",
        "import sys; sys.path.insert(0, sys.argv[1]); import release_gate, pathlib; "
        "print(release_gate.check_release(pathlib.Path(sys.argv[2]), 'tag', 'v' + sys.argv[3]))",
        str(repo / "TOOLS"), str(repo), new,
    )
    assert gate_env_ok.returncode == 0 and gate_env_ok.stdout.strip() == new, gate_env_ok.stderr

    # Tests that are bound to the committed version must follow the bump (they hard-coded
    # FREEZE_MANIFEST_v1.0.5.json until 1.1.0 and would have checked the stale manifest).
    tests = _run(
        "-m", "pytest", "-q", "-p", "no:cacheprovider",
        "tests/test_freeze_manifest.py", "tests/test_release_bundle.py",
        "tests/test_version_consistency.py::test_all_lockstep_copies_match_version",
        cwd=repo,
    )
    assert tests.returncode == 0, tests.stdout[-3000:]


@pytest.mark.parametrize(
    "case",
    ["no-release-notes", "not-newer", "same", "invalid", "drift-before", "manifest-exists"],
)
def test_bump_refusals_write_nothing(tmp_path, case):
    repo = _copy_repo(tmp_path)
    old = read_version(repo)
    new = _next(old)
    if case != "no-release-notes":
        _add_release_notes(repo, new)
    target = {"not-newer": "1.0.0", "same": old, "invalid": "1.2"}.get(case, new)
    if case == "drift-before":
        cff = repo / "CITATION.cff"
        cff.write_text(cff.read_text(encoding="utf-8").replace(f'version: "{old}"', 'version: "0.0.1"'),
                       encoding="utf-8", newline="\n")
    if case == "manifest-exists":
        (repo / "artifacts" / f"FREEZE_MANIFEST_v{new}.json").write_text("{}", encoding="utf-8")
    before = _snapshot(repo)
    proc = _run(str(repo / "TOOLS" / "version_bump.py"), target, "--root", str(repo))
    assert proc.returncode == 1, (proc.returncode, proc.stderr)
    assert "version bump refused" in proc.stderr
    assert _snapshot(repo) == before


@pytest.mark.parametrize(
    "lower, higher",
    [
        ("1.0.5", "1.1.0"),
        ("1.9.9", "1.10.0"),  # numeric, not lexical
        ("1.1.0-rc.1", "1.1.0"),  # a release outranks its pre-releases
        ("1.0.0-alpha", "1.0.0-alpha.1"),
        ("1.0.0-alpha.1", "1.0.0-alpha.beta"),  # numeric identifiers sort below alphanumeric
        ("1.0.0-alpha.beta", "1.0.0-beta"),
        ("1.0.0-beta.2", "1.0.0-beta.11"),
        ("1.0.0-beta.11", "1.0.0-rc.1"),
    ],
)
def test_semver_precedence_follows_semver_org(lower, higher):
    # semver.org section 11 example chain plus the numeric-vs-lexical trap.
    assert version_bump.is_newer(higher, lower)
    assert not version_bump.is_newer(lower, higher)


def test_build_metadata_does_not_order_versions():
    assert not version_bump.is_newer("1.1.0+build.2", "1.1.0+build.1")
    assert not version_bump.is_newer("1.1.0+build.1", "1.1.0")
