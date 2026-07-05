from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from jsonschema.exceptions import SchemaError

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "SCHEMAS"
TESTVECTORS = ROOT / "TESTVECTORS"


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _schema(name: str) -> dict:
    return _read_json(SCHEMAS / name)


def _validator(name: str) -> Draft202012Validator:
    schema = _schema(name)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


@pytest.mark.parametrize("schema_path", sorted(SCHEMAS.glob("*.schema.json")))
def test_all_json_schemas_are_valid_draft_2020_12(schema_path: Path) -> None:
    """Schema authoring errors must fail CI before fixtures are trusted."""
    try:
        Draft202012Validator.check_schema(_read_json(schema_path))
    except SchemaError as exc:  # pragma: no cover - assertion context for pytest output
        raise AssertionError(f"invalid schema: {schema_path.relative_to(ROOT)}") from exc


def test_all_committed_testvectors_match_testvector_schema() -> None:
    """Every JSON fixture under TESTVECTORS/** is itself a valid ARK testvector."""
    validator = _validator("testvector.schema.json")
    paths = sorted(TESTVECTORS.glob("**/*.json"))
    assert paths, "expected at least one committed testvector"

    failures: list[str] = []
    for path in paths:
        errors = sorted(validator.iter_errors(_read_json(path)), key=lambda e: list(e.path))
        for error in errors:
            json_path = "/".join(str(part) for part in error.path) or "<root>"
            failures.append(f"{path.relative_to(ROOT)} @ {json_path}: {error.message}")

    assert failures == []


def test_gate_report_schema_positive_and_negative_oracles() -> None:
    validator = _validator("gate_report.schema.json")
    valid = {
        "run_id": "run-001",
        "status": "ACCEPT",
        "hard_fail": [],
        "soft_fail": [],
        "warnings": [],
        "known_issues": [],
        "metrics": [],
        "gate_results": [],
        "created_utc": "2026-07-05T00:00:00Z",
    }
    validator.validate(valid)

    invalid = dict(valid)
    invalid.pop("gate_results")
    with pytest.raises(ValidationError):
        validator.validate(invalid)


def test_prov_min_schema_positive_and_negative_oracles() -> None:
    validator = _validator("prov_min.schema.json")
    valid = {
        "entities": [{"id": "entity:report", "kind": "report", "hash": None, "location_ref": None}],
        "activities": [{"id": "activity:validate", "kind": "validation", "start_utc": None, "end_utc": None, "tool_version": None}],
        "agents": [{"id": "agent:ark", "kind": "tool", "name": "ARK", "version": "1.0.5"}],
        "edges": [
            {"type": "wasGeneratedBy", "src": "entity:report", "dst": "activity:validate"},
            {"type": "wasAssociatedWith", "src": "activity:validate", "dst": "agent:ark"},
        ],
    }
    validator.validate(valid)

    invalid = dict(valid)
    invalid["edges"] = [{"type": "invalidEdge", "src": "entity:report", "dst": "activity:validate"}]
    with pytest.raises(ValidationError):
        validator.validate(invalid)


def test_report_evidence_profile_schema_positive_and_negative_oracles() -> None:
    validator = _validator("report_evidence_profile.schema.json")
    valid = {
        "run_id": "run-001",
        "status": "ACCEPT_WITH_NOTES",
        "created_utc": "2026-07-05T00:00:00Z",
        "items": [
            {
                "gate_id": "ARK-NG-002",
                "summary": "freeze manifest checked",
                "evidence_refs": ["ci:freeze-manifest"],
                "neg_ids": [],
            }
        ],
    }
    validator.validate(valid)

    invalid = dict(valid)
    invalid["items"] = [{"gate_id": "ARK-NG-002", "summary": "missing evidence refs"}]
    with pytest.raises(ValidationError):
        validator.validate(invalid)


def test_testvector_schema_positive_and_negative_oracles() -> None:
    validator = _validator("testvector.schema.json")
    valid = {
        "name": "minimal-vector",
        "inputs": {},
        "expected": {"status": "REJECT", "neg_ids": ["NEG.EXAMPLE"]},
        "tags": ["schema"],
    }
    validator.validate(valid)

    invalid = dict(valid)
    invalid["expected"] = {"neg_ids": ["NEG.EXAMPLE"]}
    with pytest.raises(ValidationError):
        validator.validate(invalid)
