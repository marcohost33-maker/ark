"""``version_bump`` after its first write: a failure puts the tree back or says it could not.

Preconditions refuse before any write (``test_version_consistency.py``). These tests fail
the bump *after* it started writing -- in each of its three tool phases, by an interrupt,
by a tool timeout -- and require the touched files to be byte-identical to before, or an
explicit ``ROLLBACK INCOMPLETE`` when a restore itself fails. They also pin the structural
check of the provenance example rewrite. Cross-family review GPT-6 R1/R4 (2026-11-21).
"""
from __future__ import annotations

import importlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "TOOLS"))

version_bump = importlib.import_module("version_bump")
release_gate = importlib.import_module("release_gate")

PROV = version_bump.PROV_EXAMPLE


def _copy_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    shutil.copytree(
        ROOT, repo, ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache", ".ruff_cache")
    )
    return repo


def _snapshot(repo: Path) -> dict[str, bytes]:
    return {
        str(p.relative_to(repo)): p.read_bytes()
        for p in sorted(repo.rglob("*"))
        if p.is_file() and "__pycache__" not in p.parts
    }


def _prepare(tmp_path: Path) -> tuple[Path, str, str]:
    repo = _copy_repo(tmp_path)
    old = release_gate.read_version(repo)
    major, minor, _ = (int(x) for x in old.split("+")[0].split("-")[0].split("."))
    new = f"{major}.{minor + 1}.0"
    path = repo / "CHANGELOG.md"
    text = path.read_text(encoding="utf-8")
    path.write_text(text.replace("## [Unreleased]\n", f"## [Unreleased]\n\n## [{new}] - unreleased\n\n- test\n", 1),
                    encoding="utf-8", newline="\n")
    return repo, old, new


def _failing_tool(monkeypatch, fail_at: int, exc: BaseException):
    """Run the real tools, but raise ``exc`` right after tool call number ``fail_at`` (1-based)."""
    real = version_bump._run_tool
    calls = []

    def tool(root, *args):
        calls.append(args)
        real(root, *args)
        if len(calls) == fail_at:
            raise exc

    monkeypatch.setattr(version_bump, "_run_tool", tool)
    return calls


# fail_at 1: after --regenerate (new manifest + lockstep edits written)
# fail_at 2: after --pin (new pin written, old pin still there)
# fail_at 3: after the final freeze gate (old pin already removed)
@pytest.mark.parametrize("fail_at", [1, 2, 3])
def test_failure_after_first_write_restores_every_byte(tmp_path, monkeypatch, fail_at):
    repo, old, new = _prepare(tmp_path)
    before = _snapshot(repo)
    calls = _failing_tool(monkeypatch, fail_at, version_bump.BumpError("injected"))
    with pytest.raises(version_bump.BumpError, match="injected -- every file the bump touched was restored"):
        version_bump.bump(repo, new)
    assert len(calls) == fail_at
    assert _snapshot(repo) == before
    assert version_bump.version_drift(repo, old) == []


def test_interrupt_restores_and_propagates(tmp_path, monkeypatch):
    repo, _, new = _prepare(tmp_path)
    before = _snapshot(repo)
    _failing_tool(monkeypatch, 2, KeyboardInterrupt())
    with pytest.raises(KeyboardInterrupt):
        version_bump.bump(repo, new)
    assert _snapshot(repo) == before


def test_failed_restore_is_reported_not_hidden(tmp_path, monkeypatch):
    repo, _, new = _prepare(tmp_path)
    _failing_tool(monkeypatch, 1, version_bump.BumpError("injected"))
    real_restore = version_bump._restore

    def restore(root, snapshot):
        failed = real_restore(root, snapshot)
        (root / "VERSION").write_text(new + "\n", encoding="utf-8")  # restore undone behind its back
        return failed + ["VERSION: simulated"]

    monkeypatch.setattr(version_bump, "_restore", restore)
    with pytest.raises(version_bump.BumpError) as info:
        version_bump.bump(repo, new)
    msg = str(info.value)
    assert msg.startswith("injected") and "ROLLBACK INCOMPLETE" in msg and "VERSION: simulated" in msg
    assert "was restored" not in msg


def test_restore_reads_back_and_names_a_silent_noop(tmp_path, monkeypatch):
    repo, _, _ = _prepare(tmp_path)
    target = repo / "VERSION"
    original = target.read_bytes()
    target.write_bytes(b"9.9.9\n")
    real_open = open

    def noop_open(path, mode="r", *a, **kw):
        if Path(path) == target and "w" in mode:
            return real_open(Path(path).parent / "VERSION.sink", mode, *a, **kw)
        return real_open(path, mode, *a, **kw)

    monkeypatch.setattr("builtins.open", noop_open)
    failed = version_bump._restore(repo, {"VERSION": original, "artifacts/never.sha256": None})
    assert failed == ["VERSION: bytes differ after restore"]


def test_tool_timeout_is_a_bump_error(tmp_path, monkeypatch):
    def timeout(*a, **kw):
        raise subprocess.TimeoutExpired(cmd="tool", timeout=300)

    monkeypatch.setattr(version_bump.subprocess, "run", timeout)
    caught: BaseException | None = None
    try:
        version_bump._run_tool(tmp_path, "freeze_manifest.py", "--regenerate")
    except BaseException as exc:  # noqa: BLE001 - the type is what is asserted
        caught = exc
    # main() maps BumpError to "version bump refused" + exit 1; a bare TimeoutExpired was a traceback.
    assert isinstance(caught, version_bump.BumpError), type(caught)
    assert "freeze_manifest.py --regenerate failed" in str(caught)


def _set_prov(repo: Path, mutate) -> None:
    path = repo / PROV
    data = json.loads(path.read_text(encoding="utf-8"))
    text = mutate(data, path.read_text(encoding="utf-8"))
    path.write_text(text, encoding="utf-8", newline="\n")


@pytest.mark.parametrize("case", ["non-tool-agent-version", "compact-layout"])
def test_provenance_rewrite_must_equal_the_structural_edit(tmp_path, case):
    repo, old, new = _prepare(tmp_path)
    if case == "non-tool-agent-version":
        # A person agent that happens to carry the old version string: the textual rewrite
        # would change it, version_drift never reads it.
        _set_prov(repo, lambda d, t: t.replace(
            '"agents": [\n',
            f'"agents": [\n    {{"id": "agent:reviewer", "kind": "person", "version": "{old}"}},\n', 1))
    else:
        # Same content, compact separators: the textual rewrite would miss the fields.
        _set_prov(repo, lambda d, t: json.dumps(d, separators=(",", ":")) + "\n")
    assert version_bump.version_drift(repo, old) == []  # a consistent tree before the bump
    before = _snapshot(repo)
    with pytest.raises(version_bump.BumpError, match="does not equal the structural one"):
        version_bump.bump(repo, new)
    assert _snapshot(repo) == before  # refused before the first write


@pytest.mark.parametrize("mode", [["--regenerate"], ["--add", "README.md"]])
def test_freeze_manifest_writes_lf_bytes_on_every_os(tmp_path, mode):
    # The bundle pin is computed over working-tree bytes; .gitattributes stores the manifest
    # as LF. A CRLF manifest written on Windows gave a pin that a fresh checkout (and CI on
    # every OS) could not reproduce (measured 2026-11-21: 2876a905... vs 8dc28c2e...).
    repo = _copy_repo(tmp_path)
    proc = subprocess.run(
        [sys.executable, "-I", str(repo / "TOOLS" / "freeze_manifest.py"), *mode],
        cwd=repo, capture_output=True, text=True, timeout=300,
    )
    assert proc.returncode == 0, proc.stderr
    manifest = repo / "artifacts" / f"FREEZE_MANIFEST_v{release_gate.read_version(repo)}.json"
    data = manifest.read_bytes()
    assert b"\r" not in data and data.endswith(b"}\n")


def test_provenance_rewrite_of_the_shipped_example_is_structural():
    old = release_gate.read_version(ROOT)
    edits = version_bump.planned_edits(ROOT, old, "99.0.0")
    data = json.loads(edits[PROV])
    assert [a["tool_version"] for a in data["activities"] if "tool_version" in a] == ["99.0.0"]
    assert [a["version"] for a in data["agents"] if a.get("kind") == "tool"] == ["99.0.0"]


def test_child_tool_runs_with_a_relative_root(tmp_path, monkeypatch):
    # Codex #46 (P2): with --root given relatively, the child script path was relative to the caller's cwd
    # while the child already ran with cwd=root, so Python looked for repo/repo/TOOLS/<tool>.
    repo = tmp_path / "repo"
    (repo / "TOOLS").mkdir(parents=True)
    (repo / "TOOLS" / "probe_ok.py").write_text("import sys\nsys.exit(0)\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    version_bump._run_tool(Path("repo"), "probe_ok.py")


def test_child_tool_failure_with_a_relative_root_is_still_reported(tmp_path, monkeypatch):
    # Negative control: resolving the root must not swallow a real tool failure.
    repo = tmp_path / "repo"
    (repo / "TOOLS").mkdir(parents=True)
    (repo / "TOOLS" / "probe_fail.py").write_text("import sys\nsys.exit(3)\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    with pytest.raises(version_bump.BumpError, match="exit 3"):
        version_bump._run_tool(Path("repo"), "probe_fail.py")
