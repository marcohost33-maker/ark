"""Release SBOM path (ARK-R8-002) and runtime-pin consistency.

Before: release.yml ran ``cyclonedx-py environment --output-format JSON --outfile
dist/sbom.cdx.json``. ``--outfile`` is not a cyclonedx-py option (exit 2), so the
first tag would have failed after the gates and before the attestation; nothing
caught it because the step only ran on tags. And the one SBOM it would have
produced described the build job (ruff, pytest, pip, cyclonedx) instead of what
the TOOLS need at runtime (GPT-6 R8 review, ARK-R8-002).

These tests drive the real cyclonedx-py CLI through ``TOOLS/release_sbom.py`` on
every PR, pin the runtime closure to the actual imports of ``TOOLS/``, and pin
the workflow wiring.
"""
from __future__ import annotations

import ast
import importlib
import importlib.metadata
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "TOOLS"))
release_sbom = importlib.import_module("release_sbom")

RUNTIME_REQ = ROOT / "requirements-runtime.txt"
CI_REQ = ROOT / "requirements-ci.txt"
RELEASE_WF = ROOT / ".github" / "workflows" / "release.yml"
CI_WF = ROOT / ".github" / "workflows" / "ci.yml"


def write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "req.txt"
    p.write_text(text, encoding="utf-8")
    return p


# --- requirements parsing -------------------------------------------------------

def test_read_pins_accepts_flat_exact_pins(tmp_path):
    p = write(tmp_path, "# c\n\nJsonSchema==4.26.0  # direct\nrpds_py==2026.9.1\n")
    assert release_sbom.read_pins(p) == {"jsonschema": "4.26.0", "rpds-py": "2026.9.1"}


@pytest.mark.parametrize("line", [
    "jsonschema>=4.26.0",
    "jsonschema",
    "jsonschema==4.*",
    "-r other.txt",
    "--index-url https://example.invalid/simple",
    "jsonschema[format]==4.26.0",
    "jsonschema==4.26.0; python_version>'3.0'",
    "jsonschema @ https://example.invalid/j.whl",
])
def test_read_pins_rejects_anything_but_exact_pins(tmp_path, line):
    with pytest.raises(release_sbom.RequirementsError):
        release_sbom.read_pins(write(tmp_path, line + "\n"))


def test_read_pins_rejects_duplicates_and_empty(tmp_path):
    with pytest.raises(release_sbom.RequirementsError, match="duplicate"):
        release_sbom.read_pins(write(tmp_path, "rpds-py==1\nrpds_py==1\n"))
    with pytest.raises(release_sbom.RequirementsError, match="no pins"):
        release_sbom.read_pins(write(tmp_path, "# only a comment\n"))


# --- component check --------------------------------------------------------------

def test_check_runtime_components_exact_match_only():
    pins = {"jsonschema": "4.26.0", "scipy": "1.17.1"}
    assert release_sbom.check_runtime_components(dict(pins), pins) == []
    errs = release_sbom.check_runtime_components(
        {"jsonschema": "4.25.0", "pip": "26.0"}, pins)
    assert errs == [
        "pinned but not in runtime SBOM: scipy==1.17.1",
        "in runtime SBOM but not pinned: pip==26.0",
        "version mismatch for jsonschema: pinned 4.26.0, SBOM 4.25.0",
    ]


def test_sbom_components_rejects_malformed():
    with pytest.raises(release_sbom.SbomError):
        release_sbom.sbom_components({"bomFormat": "CycloneDX"})
    with pytest.raises(release_sbom.SbomError):
        release_sbom.sbom_components({"components": [{"version": "1"}]})


# --- real cyclonedx-py CLI ----------------------------------------------------------

def test_generate_sbom_runs_pinned_cli_reproducibly(tmp_path):
    """The exact CLI invocation of the release path works and is byte-reproducible."""
    a = release_sbom.generate_sbom(Path(sys.executable), tmp_path / "a.json")
    release_sbom.generate_sbom(Path(sys.executable), tmp_path / "b.json")
    assert (tmp_path / "a.json").read_bytes() == (tmp_path / "b.json").read_bytes()
    names = release_sbom.sbom_components(a)
    assert "pytest" in names  # this is the build/test environment


def test_build_fails_closed_and_removes_unverified_runtime_sbom(tmp_path, monkeypatch):
    """A runtime env holding anything beyond the pins is refused; no runtime SBOM stays."""
    req = write(tmp_path, f"pytest=={importlib.metadata.version('pytest')}\n")
    monkeypatch.setattr(release_sbom, "build_runtime_env", lambda r, d: Path(sys.executable))
    out = tmp_path / "dist"
    errors = release_sbom.build(out, req)
    assert any(e.startswith("in runtime SBOM but not pinned: ruff==") for e in errors)
    assert not (out / release_sbom.RUNTIME_SBOM).exists()
    assert not (out / release_sbom.BUILD_SBOM).exists()


def test_main_usage_error_on_bad_requirements(tmp_path, capsys):
    rc = release_sbom.main(["--out", str(tmp_path / "d"), "--requirements", str(write(tmp_path, "scipy>=1\n"))])
    assert rc == 2
    assert "not an exact" in capsys.readouterr().err


# --- runtime pins == what TOOLS/ actually imports ---------------------------------------

def _third_party_imports() -> set[str]:
    local = {p.stem for p in (ROOT / "TOOLS").glob("*.py")}
    found: set[str] = set()
    for path in (ROOT / "TOOLS").glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                mods = [node.module]
            else:
                continue
            for m in mods:
                top = m.split(".")[0]
                if top not in sys.stdlib_module_names and top not in local and top != "__future__":
                    found.add(top)
    return found


def test_runtime_pins_cover_every_third_party_import_of_tools():
    pins = release_sbom.read_pins(RUNTIME_REQ)
    dists = importlib.metadata.packages_distributions()
    imports = _third_party_imports()
    assert imports, "expected jsonschema/scipy imports in TOOLS/"
    for top in sorted(imports):
        owners = {release_sbom.normalize(d) for d in dists.get(top, [])}
        assert owners & set(pins), f"TOOLS/ imports {top!r} but requirements-runtime.txt pins none of {owners or '{?}'}"


def test_ci_requirements_include_runtime_pins_instead_of_duplicating_them():
    text = CI_REQ.read_text(encoding="utf-8")
    lines = [ln.split("#", 1)[0].strip() for ln in text.splitlines()]
    lines = [ln for ln in lines if ln]
    assert "-r requirements-runtime.txt" in lines
    runtime = set(release_sbom.read_pins(RUNTIME_REQ))
    for ln in lines:
        if ln.startswith("-r "):
            continue
        name = release_sbom.normalize(ln.split("==", 1)[0])
        assert "==" in ln, f"CI pin not exact: {ln!r}"
        assert name not in runtime, f"{name} pinned in both requirements files"
    assert any(ln.startswith("cyclonedx-bom==") for ln in lines), "SBOM tool must be pinned with the CI tools"


def test_runtime_pins_match_installed_test_environment():
    """CI tests run under exactly the versions the runtime SBOM attests."""
    for name, version in release_sbom.read_pins(RUNTIME_REQ).items():
        assert importlib.metadata.version(name) == version, f"{name}: installed != pinned {version}"


# --- workflow wiring ------------------------------------------------------------------

def test_release_workflow_builds_sboms_through_the_tested_script():
    wf = RELEASE_WF.read_text(encoding="utf-8")
    assert "python TOOLS/release_sbom.py --out dist\n" in wf
    assert "cyclonedx-py" not in wf, "SBOM must not be generated inline (untested path)"
    assert wf.index("python TOOLS/release_sbom.py") < wf.index("actions/attest-build-provenance@")
    assert re.search(r'subject-path:\s*"dist/\*"', wf)


def test_ci_runs_the_release_sbom_path_on_every_pr():
    assert 'python TOOLS/release_sbom.py --out "$RUNNER_TEMP/sbom"' in CI_WF.read_text(encoding="utf-8")


def test_stated_python_floor_matches_workflows():
    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    m = re.search(r"Python ≥(\d+\.\d+)", agents)
    assert m, "AGENTS.md must state the Python floor"
    for wf in (CI_WF, RELEASE_WF):
        versions = re.findall(r'python-version:\s*"([\d.]+)"', wf.read_text(encoding="utf-8"))
        assert versions == [m.group(1)], f"{wf.name}: {versions} vs AGENTS.md ≥{m.group(1)}"
