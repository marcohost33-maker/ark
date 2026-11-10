#!/usr/bin/env python3
"""Release SBOMs: runtime closure and build environment (ARK-R8-002).

Run by ``.github/workflows/release.yml`` after the gates and before the
attestation, and by ``ci.yml`` on every PR so the release path cannot rot
unnoticed (the inline ``cyclonedx-py environment --outfile ...`` it replaces
never ran: ``--outfile`` is not a cyclonedx-py option, exit 2, and no tag had
ever been pushed to expose it).

Two SBOMs, two subjects, each named for what it describes:

* ``sbom.runtime.cdx.json`` -- what a consumer needs to *run* the TOOLS. Built
  from a fresh virtual environment (no pip inside) that contains only
  ``requirements-runtime.txt``. Before the SBOM is accepted, its component set
  must equal the pinned set exactly: same names, same versions, nothing missing,
  nothing extra. An unpinned transitive dependency or a stray tool fails closed.
* ``sbom.build.cdx.json`` -- the release job's own environment (test and SBOM
  tooling included). This is what the old single SBOM described; it stays, but
  is no longer presented as the runtime.

Both are written with ``--output-reproducible``: identical environments give
byte-identical SBOMs.

Exit codes: 0 OK, 1 check failed (SBOM does not match the pins, tool failed),
2 usage error (unreadable or malformed requirements file).
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
import venv
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_REQUIREMENTS = ROOT / "requirements-runtime.txt"
RUNTIME_SBOM = "sbom.runtime.cdx.json"
BUILD_SBOM = "sbom.build.cdx.json"

# PEP 508 name, then exactly one ``==`` pin with a plain version (no markers,
# extras, URLs, ranges or wildcards). Anything else is a usage error.
_PIN_RE = re.compile(r"([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)==([A-Za-z0-9][A-Za-z0-9.+!_-]*)", re.ASCII)


class RequirementsError(ValueError):
    """The requirements file is not a flat list of exact pins."""


class SbomError(RuntimeError):
    """SBOM generation failed or the SBOM does not match the pins."""


def normalize(name: str) -> str:
    """PEP 503 normalized distribution name."""
    return re.sub(r"[-_.]+", "-", name).lower()


def read_pins(path: Path) -> Dict[str, str]:
    """Return ``{normalized name: version}`` from a flat exact-pin file.

    Blank lines and ``#`` comments are allowed; every other line must be
    ``name==version``. Includes (``-r``), options, ranges and duplicates raise.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise RequirementsError(f"{path}: unreadable: {exc}") from exc
    pins: Dict[str, str] = {}
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = _PIN_RE.fullmatch(line)
        if m is None:
            raise RequirementsError(f"{path}:{lineno}: not an exact 'name==version' pin: {raw.strip()!r}")
        name = normalize(m.group(1))
        if name in pins:
            raise RequirementsError(f"{path}:{lineno}: duplicate pin for {name!r}")
        pins[name] = m.group(2)
    if not pins:
        raise RequirementsError(f"{path}: no pins")
    return pins


def sbom_components(sbom: dict) -> Dict[str, str]:
    """Return ``{normalized name: version}`` of the SBOM's components."""
    comps = sbom.get("components") if isinstance(sbom, dict) else None
    if not isinstance(comps, list):
        raise SbomError("SBOM has no components list")
    out: Dict[str, str] = {}
    for c in comps:
        if not isinstance(c, dict) or not isinstance(c.get("name"), str):
            raise SbomError(f"SBOM component without a name: {c!r}")
        out[normalize(c["name"])] = str(c.get("version", ""))
    return out


def check_runtime_components(components: Dict[str, str], pins: Dict[str, str]) -> List[str]:
    """Differences between the runtime SBOM and the pins; empty list = exact match."""
    errors: List[str] = []
    for name in sorted(set(pins) - set(components)):
        errors.append(f"pinned but not in runtime SBOM: {name}=={pins[name]}")
    for name in sorted(set(components) - set(pins)):
        errors.append(f"in runtime SBOM but not pinned: {name}=={components[name]}")
    for name in sorted(set(pins) & set(components)):
        if pins[name] != components[name]:
            errors.append(f"version mismatch for {name}: pinned {pins[name]}, SBOM {components[name]}")
    return errors


def generate_sbom(python: Path, outfile: Path) -> dict:
    """Run cyclonedx-py over the environment of ``python``; return the parsed SBOM."""
    cmd = [sys.executable, "-m", "cyclonedx_py", "environment",
           "--output-format", "JSON", "--output-reproducible",
           "--output-file", str(outfile), str(python)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise SbomError(f"cyclonedx-py exit {proc.returncode}: {proc.stderr.strip()}")
    try:
        sbom = json.loads(outfile.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SbomError(f"SBOM {outfile} unreadable: {exc}") from exc
    if not isinstance(sbom, dict) or sbom.get("bomFormat") != "CycloneDX":
        raise SbomError(f"{outfile} is not a CycloneDX document")
    return sbom


def build_runtime_env(requirements: Path, env_dir: Path) -> Path:
    """Create a pip-less venv with only ``requirements`` installed; return its python."""
    venv.EnvBuilder(with_pip=False, clear=True).create(env_dir)
    python = env_dir / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    cmd = [sys.executable, "-m", "pip", "--python", str(python), "install",
           "--disable-pip-version-check", "--no-input", "-r", str(requirements)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise SbomError(f"runtime install failed (exit {proc.returncode}): {proc.stderr.strip()}")
    return python


def build(out_dir: Path, requirements: Path = RUNTIME_REQUIREMENTS) -> List[str]:
    """Write both SBOMs into ``out_dir``. Returns the runtime check errors (empty = OK)."""
    pins = read_pins(requirements)
    out_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ark-runtime-") as tmp:
        python = build_runtime_env(requirements, Path(tmp) / "venv")
        runtime = generate_sbom(python, out_dir / RUNTIME_SBOM)
    errors = check_runtime_components(sbom_components(runtime), pins)
    if errors:
        (out_dir / RUNTIME_SBOM).unlink()  # never leave an unverified runtime SBOM behind
        return errors
    generate_sbom(Path(sys.executable), out_dir / BUILD_SBOM)
    return []


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", required=True, type=Path, help="output directory (e.g. dist)")
    ap.add_argument("--requirements", type=Path, default=RUNTIME_REQUIREMENTS,
                    help="flat exact-pin runtime requirements (default: requirements-runtime.txt)")
    args = ap.parse_args(argv)
    try:
        errors = build(args.out, args.requirements)
    except RequirementsError as exc:
        print(f"release_sbom: {exc}", file=sys.stderr)
        return 2
    except SbomError as exc:
        print(f"release_sbom: {exc}", file=sys.stderr)
        return 1
    if errors:
        for e in errors:
            print(f"release_sbom: {e}", file=sys.stderr)
        return 1
    print(f"release_sbom: {RUNTIME_SBOM} matches {args.requirements.name}; {BUILD_SBOM} written")
    return 0


if __name__ == "__main__":
    sys.exit(main())
