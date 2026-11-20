from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "TOOLS"
sys.path.insert(0, str(TOOLS))


VALID_SEMVER = [
    "1.2.3",
    "1.0.0-alpha.1",
    "1.0.0-0.3.7",
    "1.0.0+build.1",
    "1.0.0-rc.1+build.5",
    "0.0.0",
    "10.20.30",
    "1.0.0-alpha",
    "1.0.0-x.7.z.92",
]

# Strings the official SemVer 2.0.0 spec rejects but the old lax pattern accepted.
INVALID_SEMVER = [
    "1.2.3-0123",        # leading zero in numeric prerelease identifier
    "1.2.3-0123.0123",   # leading zeros in numeric prerelease identifiers
    "1.0.0-alpha..",     # empty prerelease identifier
    "1.0.0-",            # empty prerelease
    "01.2.3",            # leading zero in major
    "1.2",               # not enough parts
    "1.0.0-alpha_beta",  # underscore not allowed
    "1.0.1" + chr(0xFF15),  # fullwidth digit 5: \d matched it (ARK-EQ-01)
    "1.0.1" + chr(0x0665),  # Arabic-Indic digit 5 (ARK-EQ-01)
    chr(0xFF11) + ".0.0",   # fullwidth major
    "1.2.3\n",           # "$" matched before a trailing newline
]


@pytest.fixture(scope="module")
def validate_run_mod():
    return importlib.import_module("validate_run")


@pytest.mark.parametrize("version", VALID_SEMVER)
def test_semver_accepts_valid(validate_run_mod, version):
    assert validate_run_mod.SEMVER_RE.match(version) is not None, version


@pytest.mark.parametrize("version", INVALID_SEMVER)
def test_semver_rejects_invalid(validate_run_mod, version):
    assert validate_run_mod.SEMVER_RE.match(version) is None, version


def test_kernel_payload_flags_invalid_semver(validate_run_mod):
    neg = validate_run_mod.check_kernel_payload(
        {"content_hash": "x", "version": "1.2.3-0123", "payload": {}}
    )
    assert "NEG.KERNEL.INVALID_SEMVER" in neg


def test_kernel_payload_accepts_valid_semver(validate_run_mod):
    neg = validate_run_mod.check_kernel_payload(
        {"content_hash": "x", "version": "1.0.0-rc.1+build.5", "payload": {}}
    )
    assert "NEG.KERNEL.INVALID_SEMVER" not in neg


@pytest.mark.parametrize("version", ["1.0.1" + chr(0xFF15), "1.0.1" + chr(0x0665)], ids=["fullwidth-5", "arabic-indic-5"])
def test_kernel_payload_flags_non_ascii_digits(validate_run_mod, version):
    # ARK-EQ-01: a Unicode-aware digit class accepts U+FF15 / U+0665; SemVer is ASCII.
    neg = validate_run_mod.check_kernel_payload({"content_hash": "x", "version": version, "payload": {}})
    assert "NEG.KERNEL.INVALID_SEMVER" in neg, f"Expected: {version!a} rejected; Observed: accepted"


def test_kernel_payload_flags_trailing_newline(validate_run_mod):
    # check_kernel_payload uses SEMVER_RE.match; with "$" instead of "\Z" the
    # pattern matched before a trailing newline and "1.2.3\n" passed.
    neg = validate_run_mod.check_kernel_payload({"content_hash": "x", "version": "1.2.3\n", "payload": {}})
    assert "NEG.KERNEL.INVALID_SEMVER" in neg, "Expected: '1.2.3\n' rejected; Observed: accepted"


def test_one_grammar_for_kernel_check_and_release_gate(validate_run_mod):
    ark_semver = importlib.import_module("ark_semver")
    release_gate = importlib.import_module("release_gate")
    assert validate_run_mod.SEMVER_RE is ark_semver.SEMVER_RE
    assert release_gate.SEMVER_RE is ark_semver.SEMVER_RE
