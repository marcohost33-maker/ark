"""Release gate (cross-family review 2026-10-19, ARK-P1-01 / ARK-P1-02).

Before: ``release.yml`` checked VERSION with a shell character class, so
``invalid-version``/``1.0.5.6``/``01.0.5`` passed whenever tag and manifest name
matched, and a manual dispatch on a branch passed with no tag at all. These tests
run the real gate (``TOOLS/release_gate.py``) as a subprocess with GitHub's env
vars, and pin the workflow wiring: tag-only job, gate first, full test suite
before anything is built or attested.
"""
from __future__ import annotations

import importlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "TOOLS"))
release_gate = importlib.import_module("release_gate")

from test_semver import INVALID_SEMVER, VALID_SEMVER  # noqa: E402

GATE = ROOT / "TOOLS" / "release_gate.py"
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"


def make_repo(tmp: Path, version_bytes: bytes, *, manifest: str | None = "auto", artifact: str | None = None) -> Path:
    repo = tmp / "repo"
    (repo / "artifacts").mkdir(parents=True)
    (repo / "VERSION").write_bytes(version_bytes)
    if manifest == "auto":
        v = version_bytes.decode("utf-8", errors="replace").strip()
        name = f"FREEZE_MANIFEST_v{v}.json"
        body = {"artifact": artifact if artifact is not None else f"ARK-Core_v{v}_freeze"}
        (repo / "artifacts" / name).write_text(json.dumps(body), encoding="utf-8")
    elif manifest is not None:
        (repo / "artifacts" / manifest[0]).write_text(manifest[1], encoding="utf-8")
    return repo


def run_gate(repo: Path, ref_type: str | None, ref_name: str | None, *, argv: list[str] | None = None,
             cwd: Path | None = None) -> tuple[int, str | None, str]:
    out = repo.parent / "github_output"
    if out.exists():
        out.unlink()
    env = {k: v for k, v in os.environ.items() if not k.startswith("GITHUB_")}
    env["GITHUB_OUTPUT"] = str(out)
    if ref_type is not None:
        env["GITHUB_REF_TYPE"] = ref_type
    if ref_name is not None:
        env["GITHUB_REF_NAME"] = ref_name
    cmd = argv if argv is not None else [sys.executable, str(GATE), "--root", str(repo)]
    proc = subprocess.run(cmd, cwd=cwd or repo, env=env, capture_output=True, text=True, timeout=60)
    written = out.read_text(encoding="utf-8") if out.exists() else None
    return proc.returncode, written, proc.stderr


# ------------------------------- positive controls ------------------------------- #
@pytest.mark.parametrize("version", ["1.0.5", "1.1.0", "2.0.0-rc.1", "1.0.0+build.5"])
def test_tag_release_with_strict_semver_passes(tmp_path, version):
    repo = make_repo(tmp_path, f"{version}\n".encode())
    rc, written, err = run_gate(repo, "tag", f"v{version}")
    assert rc == 0, err
    assert written == f"version={version}\n"


def test_current_repository_would_release_on_its_own_tag(tmp_path):
    version = release_gate.read_version(ROOT)
    assert release_gate.check_release(ROOT, "tag", f"v{version}") == version


# ------------------------- ARK-P1-01: grammar, not charset ------------------------ #
@pytest.mark.parametrize(
    "version",
    ["invalid-version", "1.0.5.6", "01.0.5", "1.0", "1.2.3-0123", "1.0.0-alpha..", "1.0.0-alpha_beta",
     "1.0.5;rm -rf x", "v1.0.5"],
)
def test_invalid_version_is_refused_even_with_matching_tag_and_manifest(tmp_path, version):
    # Strongest forger: tag == "v" + VERSION and a manifest with the matching name
    # and artifact field exist, so only the SemVer grammar can refuse.
    repo = make_repo(tmp_path, f"{version}\n".encode())
    assert (repo / "artifacts" / f"FREEZE_MANIFEST_v{version}.json").is_file()
    rc, written, err = run_gate(repo, "tag", f"v{version}")
    assert rc == 1, f"Expected: refused; Observed: rc={rc}, output={written!r}"
    assert written is None
    assert "SemVer" in err


@pytest.mark.parametrize("raw", [b"1.0.5", b"1.0.5\r\n", b"1.0.5\n\n", b"\n", b"", b"\xef\xbb\xbf1.0.5\n", b"1.0.5 \n",
                                 b"\xff\xfe1\n"])
def test_malformed_version_file_is_refused(tmp_path, raw):
    repo = make_repo(tmp_path, raw, manifest=None)
    rc, written, _ = run_gate(repo, "tag", "v1.0.5")
    assert rc == 1 and written is None


def test_same_semver_rule_as_the_version_tests():
    for version in VALID_SEMVER:
        assert release_gate.is_semver(version), version
    for version in INVALID_SEMVER + ["1.0.5\n", "1.0.5.6", "invalid-version"]:
        assert not release_gate.is_semver(version), version


# --------------------------- ARK-P1-02: tag refs only ---------------------------- #
@pytest.mark.parametrize("ref_type, ref_name", [("branch", "main"), ("branch", "v1.0.5"), (None, None), ("", "v1.0.5"),
                                                ("Tag", "v1.0.5")])
def test_non_tag_ref_is_refused(tmp_path, ref_type, ref_name):
    # ("branch", "v1.0.5"): a branch deliberately named like the tag must not pass.
    repo = make_repo(tmp_path, b"1.0.5\n")
    rc, written, err = run_gate(repo, ref_type, ref_name)
    assert rc == 1, f"Expected: non-tag ref refused; Observed: rc={rc}, output={written!r}"
    assert written is None


@pytest.mark.parametrize("ref_name", ["v1.1.0", "1.0.5", "v1.0.5-rc.1", "v1.0.5 ", "refs/tags/v1.0.5"])
def test_tag_must_equal_v_version(tmp_path, ref_name):
    repo = make_repo(tmp_path, b"1.0.5\n")
    rc, written, _ = run_gate(repo, "tag", ref_name)
    assert rc == 1 and written is None


@pytest.mark.parametrize(
    "manifest",
    [None, ("FREEZE_MANIFEST_v1.0.5.json", "not json"), ("FREEZE_MANIFEST_v1.0.5.json", "[]"),
     ("FREEZE_MANIFEST_v1.0.5.json", json.dumps({"artifact": "ARK-Core_v1.0.4_freeze"}))],
)
def test_manifest_must_exist_and_name_the_version(tmp_path, manifest):
    repo = make_repo(tmp_path, b"1.0.5\n", manifest=manifest)
    rc, written, _ = run_gate(repo, "tag", "v1.0.5")
    assert rc == 1 and written is None


def test_missing_github_output_is_a_usage_error(tmp_path):
    repo = make_repo(tmp_path, b"1.0.5\n")
    env = {k: v for k, v in os.environ.items() if not k.startswith("GITHUB_")}
    env.update(GITHUB_REF_TYPE="tag", GITHUB_REF_NAME="v1.0.5")
    proc = subprocess.run([sys.executable, str(GATE), "--root", str(repo)], env=env, capture_output=True, timeout=60)
    assert proc.returncode == 2


# ------------------------------- workflow wiring ------------------------------- #
def _workflow() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def _jobs(wf: str) -> dict[str, str]:
    body = wf.split("\njobs:\n", 1)[1]
    parts = re.split(r"(?m)^  ([A-Za-z0-9_-]+):\n", body)
    return dict(zip(parts[1::2], parts[2::2]))


def _step_index(job: str, needle: str) -> int:
    index = job.find(needle)
    assert index >= 0, f"step {needle!r} missing from release.yml"
    return index


def test_every_release_job_runs_only_on_tag_refs():
    jobs = _jobs(_workflow())
    assert jobs, "no jobs parsed from release.yml"
    for name, job in jobs.items():
        header = job.split("    steps:", 1)[0]
        assert re.search(r"(?m)^    if: github\.ref_type == 'tag'$", header), (
            f"Expected: job {name!r} skipped on non-tag refs; Observed: no tag-only condition"
        )


def test_gate_and_tests_run_before_build_and_attestation():
    job = _jobs(_workflow())["provenance"]
    gate = _step_index(job, "run: python TOOLS/release_gate.py\n")
    tests = _step_index(job, "run: pytest -q\n")
    freeze = _step_index(job, "run: python TOOLS/freeze_manifest.py\n")
    build = _step_index(job, "- name: Build release artifacts")
    attest = _step_index(job, "actions/attest-build-provenance@")
    upload = _step_index(job, "actions/upload-artifact@")
    assert gate < tests < freeze < build < attest < upload
    assert "id: version" in job[:gate]


def test_workflow_gate_command_refuses_invalid_version(tmp_path):
    # Execute the exact command of the workflow's gate step (python -> this interpreter)
    # in a copy of the repo with an invalid VERSION, a matching tag and a matching manifest.
    match = re.search(r"(?m)^        id: version\n(?:        #.*\n)*        run: (.+)$", _workflow())
    assert match, "gate step command not found in release.yml"
    argv = shlex.split(match.group(1))
    assert argv[:2] == ["python", "TOOLS/release_gate.py"], f"gate step runs {argv!r}"
    repo = make_repo(tmp_path, b"1.0.5.6\n")
    shutil.copytree(ROOT / "TOOLS", repo / "TOOLS", ignore=shutil.ignore_patterns("__pycache__"))
    rc, written, _ = run_gate(repo, "tag", "v1.0.5.6", argv=[sys.executable, *argv[1:]], cwd=repo)
    assert rc == 1 and written is None, f"Expected: refused; Observed: rc={rc}, output={written!r}"
    (repo / "VERSION").write_bytes(b"1.0.5\n")
    (repo / "artifacts" / "FREEZE_MANIFEST_v1.0.5.json").write_text(
        json.dumps({"artifact": "ARK-Core_v1.0.5_freeze"}), encoding="utf-8"
    )
    rc, written, err = run_gate(repo, "tag", "v1.0.5", argv=[sys.executable, *argv[1:]], cwd=repo)
    assert rc == 0 and written == "version=1.0.5\n", err
