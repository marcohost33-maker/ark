#!/usr/bin/env python3
"""Minimal, deterministic end-to-end ARK pipeline (issue #17).

Flow:  validate_run  ->  provenance validation  ->  report/evidence profile.

Run:
    py examples/run_pipeline.py --run examples/minimal_run

Deterministic replay: every field of both output artifacts is fixed for the
committed ``examples/minimal_run`` inputs except ``created_utc`` (wall clock).
The golden test (``tests/test_example_minimal_run.py``) normalizes that single
field, so re-running yields byte-identical artifacts modulo the timestamp.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "TOOLS"))

import validate_run as vr  # noqa: E402
from jsonschema import Draft202012Validator  # noqa: E402
from provenance_validate import validate_prov_min  # noqa: E402

SCHEMAS = os.path.join(ROOT, "SCHEMAS")


def _read_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _validator(schema_name: str) -> Draft202012Validator:
    schema = _read_json(os.path.join(SCHEMAS, schema_name))
    return Draft202012Validator(schema, format_checker=vr.strict_format_checker())


def run_pipeline(run_dir: str) -> dict:
    """Execute the three stages; return {gate_report, prov_neg_ids, evidence_profile}."""
    # Stage 1 — gate validation (also self-validates the report schema).
    gate_report = vr.validate_run(run_dir)

    # Stage 2 — provenance: schema shape + semantic minimal-graph check.
    prov_doc = _read_json(os.path.join(run_dir, "provenance", "prov.json"))
    _validator("prov_min.schema.json").validate(prov_doc)  # raises on bad shape
    prov_neg_ids = validate_prov_min(prov_doc)

    # Stage 3 — evidence profile (REPORTING_POLICY_v1).
    evidence_profile = {
        "run_id": gate_report["run_id"],
        "status": gate_report["status"],
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "items": [
            {
                "gate_id": "ARK-KERNEL",
                "summary": "five kernel files present and payload-valid",
                "evidence_refs": ["reports/gate_report.json"],
                "neg_ids": gate_report["hard_fail"] + gate_report["soft_fail"],
            },
            {
                "gate_id": "ARK-PROV",
                "summary": "provenance minimal graph is complete",
                "evidence_refs": ["provenance/prov.json"],
                "neg_ids": prov_neg_ids,
            },
        ],
    }
    _validator("report_evidence_profile.schema.json").validate(evidence_profile)
    return {
        "gate_report": gate_report,
        "prov_neg_ids": prov_neg_ids,
        "evidence_profile": evidence_profile,
    }


def _write_json(path: str, obj: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, sort_keys=True)
        f.write("\n")


def main() -> int:
    ap = argparse.ArgumentParser(description="Minimal ARK pipeline example.")
    ap.add_argument("--run", default=os.path.join("examples", "minimal_run"))
    ap.add_argument("--out-dir", default=None, help="Defaults to <run>/reports")
    args = ap.parse_args()

    result = run_pipeline(args.run)
    out_dir = args.out_dir or os.path.join(args.run, "reports")
    _write_json(os.path.join(out_dir, "gate_report.json"), result["gate_report"])
    _write_json(os.path.join(out_dir, "evidence_profile.json"), result["evidence_profile"])

    gr = result["gate_report"]
    print(
        f"STATUS={gr['status']} "
        f"hard={len(gr['hard_fail'])} soft={len(gr['soft_fail'])} "
        f"warn={len(gr['warnings'])} prov_neg={len(result['prov_neg_ids'])}"
    )
    print(f"artifacts -> {out_dir}/gate_report.json, {out_dir}/evidence_profile.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
