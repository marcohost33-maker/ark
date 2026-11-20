"""The one JSON grammar of ARK: I-JSON (RFC 7493), ``TOOLS/ark_json.py``.

Python's ``json`` accepts three things other readers of the same bytes read differently
or refuse: duplicate member names, ``NaN``/``Infinity`` and unpaired surrogates /
noncharacters. Every tool that decides on JSON input uses ``ark_json``, so the verdict
does not depend on which parser reads the file. Covered here: the grammar itself, each
consumer's mapping to its existing NEG ID / error, and a structural "one grammar" rule.
"""
from __future__ import annotations

import ast
import importlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "TOOLS"))
sys.path.insert(0, str(ROOT / "tests"))

ark_json = importlib.import_module("ark_json")
validate_run = importlib.import_module("validate_run")
release_gate = importlib.import_module("release_gate")

from test_hardening_wave2 import _write_kernels  # noqa: E402


# ------------------------------- positive controls ------------------------------- #
@pytest.mark.parametrize(
    "text",
    [
        '{"a": 1, "b": [1.5, -2, 0, null, true, false], "c": {"a": "x"}}',  # same name in different objects
        '[]',
        '"plain"',
        '1e308',
        '"\\ud83d\\ude00"',  # escaped surrogate PAIR = one astral code point (U+1F600): valid
        '"\U0001F600 ä 中"',
        '{"k": "\\uFFFD"}',  # replacement character is a character, not a noncharacter
    ],
)
def test_accepts_what_i_json_allows_and_matches_json(text):
    assert ark_json.loads(text) == json.loads(text)


def test_repository_json_is_i_json():
    """Every committed JSON document (schemas, testvectors, examples, manifest) parses."""
    paths = [p for p in ROOT.rglob("*.json") if ".git" not in p.parts]
    assert paths
    for path in paths:
        ark_json.load_path(str(path))


# ------------------------------- refusals ------------------------------- #
@pytest.mark.parametrize(
    "text",
    [
        '{"a": 1, "a": 2}',
        '{"a": 1, "\\u0061": 2}',  # equal after escape processing (RFC 7493 2.3)
        '{"x": {"files": [], "files": ["y"]}}',  # nested
        '[{"a": 1}, {"b": 1, "b": 1}]',  # equal values are still two members
    ],
    ids=["plain", "escaped-equal", "nested", "in-array"],
)
def test_duplicate_member_names_are_refused(text):
    with pytest.raises(ark_json.StrictJSONError, match="duplicate"):
        ark_json.loads(text)


@pytest.mark.parametrize("text", ["NaN", "[Infinity]", '{"a": -Infinity}'])
def test_non_finite_numbers_are_refused(text):
    with pytest.raises(ark_json.StrictJSONError, match="non-finite"):
        ark_json.loads(text)


@pytest.mark.parametrize(
    "text",
    [
        '"\\ud800"',  # lone high surrogate, top level
        '["ok", "\\udead"]',  # lone low surrogate, array element
        '{"k": "\\ud83d"}',  # unpaired high surrogate, member value
        '{"\\udc00": 1}',  # surrogate in a member name
        '"\\ude00\\ud83d"',  # pair in the wrong order
        '{"k": "\\uFFFE"}',
        '{"k": "\\uFDD0"}',
        '["\\ud83f\\udfff"]',  # U+1FFFF, a noncharacter outside the BMP
        '{"a": [["\\uFFFF"]]}',  # deep inside arrays
        '"﷯"',  # unescaped noncharacter
    ],
)
def test_surrogates_and_noncharacters_are_refused(text):
    with pytest.raises(ark_json.StrictJSONError, match="surrogate|noncharacter"):
        ark_json.loads(text)


def test_every_refusal_is_a_value_error():
    """Callers already map ValueError to their unreadable-input NEG ID."""
    assert issubclass(ark_json.StrictJSONError, ValueError)


# --------------------- consumers map refusals to existing outcomes --------------------- #
@pytest.mark.parametrize(
    "content",
    [
        # A first-wins reader sees an invalid version, Python's json sees a valid one.
        '{"content_hash": "sha256:env", "version": "x", "version": "1.0.0", "payload": {}}',
        '{"content_hash": "sha256:env", "version": "1.0.0", "payload": {"t": NaN}}',
        '{"content_hash": "sha256:env", "version": "1.0.0", "payload": {"t": "\\ud800"}}',
    ],
    ids=["duplicate", "nan", "surrogate"],
)
def test_validate_run_rejects_a_non_i_json_kernel_as_unreadable(tmp_path, content):
    kdir = _write_kernels(tmp_path / "run")
    (kdir / "kernel.env.json").write_text(content, encoding="utf-8")
    report = validate_run.validate_run(str(tmp_path / "run"))
    assert report["status"] == "REJECT"
    assert report["hard_fail"] == ["NEG.KERNEL.UNREADABLE"]


def test_validate_run_refuses_a_policy_with_a_duplicate_member(tmp_path):
    # A first-wins reader would see a waiver that Python's json drops.
    path = tmp_path / "policy.json"
    path.write_text('{"waivers": ["NEG.X.Y"], "waivers": []}', encoding="utf-8")
    with pytest.raises(validate_run.PolicyError, match="duplicate"):
        validate_run.load_policy(str(path))


def test_release_gate_refuses_a_manifest_with_a_duplicate_member(tmp_path):
    repo = tmp_path / "repo"
    (repo / "artifacts").mkdir(parents=True)
    (repo / "VERSION").write_bytes(b"1.0.5\n")
    (repo / "artifacts" / "FREEZE_MANIFEST_v1.0.5.json").write_text(
        '{"artifact": "ARK-Core_v0.0.1_freeze", "artifact": "ARK-Core_v1.0.5_freeze"}', encoding="utf-8"
    )
    with pytest.raises(release_gate.ReleaseGateError, match="duplicate"):
        release_gate.check_release(repo, "tag", "v1.0.5")


# ------------------------------- one grammar ------------------------------- #
def test_no_tool_parses_json_outside_ark_json():
    """Like ``ark_semver`` for SemVer: one JSON grammar for every decision path."""
    offenders = []
    for path in sorted((ROOT / "TOOLS").glob("*.py")):
        if path.name == "ark_json.py":
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if (
                isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id == "json"
                and node.attr in {"load", "loads", "JSONDecoder"}
            ):
                offenders.append(f"{path.name}:{node.lineno} json.{node.attr}")
    assert offenders == []
