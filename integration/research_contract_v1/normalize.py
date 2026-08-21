from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

PROMOTED = {"PROVEN", "BENCHMARKED", "SUPPORTED", "PASS", "VERIFIED"}
PASS_EVIDENCE = {"PASS", "VERIFIED"}
EX_NOINPUT = 66


def _canon(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canon(value)).hexdigest()


def _id(obj: dict[str, Any]) -> str:
    for key in ("evidence_id", "gate_id", "report_id", "claim_id", "run_id", "model_id"):
        if obj.get(key):
            return str(obj[key])
    return _digest(obj)[7:23]


def _record(kind: str, obj: dict[str, Any]) -> dict[str, Any]:
    rec: dict[str, Any] = {
        "record_type": kind,
        "source_id": _id(obj),
        "source_schema": obj.get("schema_name") or obj.get("type") or "unknown",
        "source_object": obj,
    }
    if "source_revision" in obj:
        rec["source_revision"] = obj["source_revision"]
    elif "evaluator_revision" in obj:
        rec["source_revision"] = obj["evaluator_revision"]
    if "material_digest" in obj:
        rec["material_digest"] = obj["material_digest"]
    elif "input_digest" in obj:
        rec["material_digest"] = obj["input_digest"]
    return rec


def _contradiction(code: str, subject: str, detail: str, source_ids: list[str]) -> dict[str, Any]:
    return {
        "record_type": "contradiction",
        "code": code,
        "severity": "HARD_FAIL",
        "blocking": True,
        "subject_id": subject,
        "detail": detail,
        "source_ids": sorted(set(source_ids)),
    }


def normalize(bundle: dict[str, Any]) -> dict[str, Any]:
    claim = bundle.get("claim_card") or {}
    run = bundle.get("run_plan") or {}
    evidence = [x for x in bundle.get("evidence_attestations", []) if isinstance(x, dict)]
    gates = [x for x in bundle.get("gate_reports", []) if isinstance(x, dict)]
    supersession = [x for x in bundle.get("supersession_reports", []) if isinstance(x, dict)]

    records = [_record("provenance.evidence_attestation", x) for x in evidence]
    records += [_record("event.gate_report", x) for x in gates]
    records += [_record("event.supersession_report", x) for x in supersession]

    contradictions: list[dict[str, Any]] = []
    claim_id = str(claim.get("claim_id", "<missing-claim>"))
    run_id = str(run.get("run_id", "<missing-run>"))
    promoted = claim.get("status") in PROMOTED
    by_id = {str(x.get("evidence_id")): x for x in evidence if x.get("evidence_id")}
    referenced = [str(x) for x in claim.get("evidence_ids", [])]

    if promoted:
        for evid in referenced:
            item = by_id.get(evid)
            if item is None:
                contradictions.append(_contradiction(
                    "RC.EVIDENCE.MISSING", claim_id, f"Promoted claim references missing evidence {evid}.", [claim_id, evid]
                ))
                continue
            subject = item.get("subject") or {}
            if item.get("verdict") not in PASS_EVIDENCE:
                contradictions.append(_contradiction(
                    "RC.EVIDENCE.NON_PASS", claim_id,
                    f"Promoted claim references evidence {evid} with verdict {item.get('verdict')!r}.",
                    [claim_id, evid],
                ))
            if item.get("stale") is True:
                contradictions.append(_contradiction(
                    "RC.EVIDENCE.STALE", claim_id, f"Promoted claim references stale evidence {evid}.", [claim_id, evid]
                ))
            if subject.get("claim_id") != claim_id or subject.get("run_id") != run_id:
                contradictions.append(_contradiction(
                    "RC.EVIDENCE.UNBOUND", claim_id,
                    f"Evidence {evid} is not bound to claim={claim_id} and run={run_id}.",
                    [claim_id, run_id, evid],
                ))
            if not item.get("material_digest") or not item.get("source_revision"):
                contradictions.append(_contradiction(
                    "RC.EVIDENCE.PROVENANCE_INCOMPLETE", claim_id,
                    f"Evidence {evid} lacks material_digest or source_revision.", [claim_id, evid]
                ))

        required_oracles = {str(x) for x in run.get("required_oracles", [])}
        covered = {
            str(x.get("oracle_id"))
            for x in evidence
            if x.get("evidence_id") in referenced
            and x.get("verdict") in PASS_EVIDENCE
            and x.get("stale") is not True
            and x.get("oracle_id")
        }
        for oracle in sorted(required_oracles - covered):
            contradictions.append(_contradiction(
                "RC.ORACLE.MISSING", claim_id,
                f"Required oracle {oracle} has no current passing referenced evidence.",
                [claim_id, run_id, oracle],
            ))

    for report in supersession:
        stale = report.get("stale_dependencies") or report.get("stale_dependency_ids") or []
        failed = report.get("result") == "FAIL" or report.get("valid") is False
        if failed:
            contradictions.append(_contradiction(
                "RC.SUPERSESSION.FAIL", _id(report), "Supersession report is explicitly failing.", [_id(report)]
            ))
        if stale:
            contradictions.append(_contradiction(
                "RC.SUPERSESSION.STALE_DEPENDENCY", _id(report),
                f"Supersession report contains stale dependencies: {sorted(map(str, stale))}.",
                [_id(report), *map(str, stale)],
            ))

    blocking_claim_codes = {c["subject_id"] for c in contradictions if c.get("blocking")}
    if claim_id in blocking_claim_codes:
        for gate in gates:
            if gate.get("result") == "PASS" and str(gate.get("subject_id")) == claim_id:
                contradictions.append(_contradiction(
                    "RC.GATE.PASS_WITH_BLOCKING_CONTRADICTION", str(gate.get("gate_id", "<missing-gate>")),
                    "PASS gate targets a claim with blocking evidence contradictions.",
                    [str(gate.get("gate_id", "<missing-gate>")), claim_id],
                ))

    records.sort(key=lambda r: (r["record_type"], r["source_id"]))
    contradictions.sort(key=lambda c: (c["code"], c["subject_id"], c["detail"]))
    payload = {
        "schema_name": "ARKResearchContractNormalization",
        "schema_version": "1.0.0-candidate",
        "source": bundle.get("source", {}),
        "claim_id": claim.get("claim_id"),
        "run_id": run.get("run_id"),
        "records": records,
        "contradictions": contradictions,
        "blocking": any(c.get("blocking") for c in contradictions),
        "trust_boundary": "ARK normalization PASS is audit/provenance evidence only; it is not scientific truth.",
    }
    payload["output_digest"] = _digest(payload)
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Normalize Research Contract v1 evidence into deterministic ARK records.")
    parser.add_argument("input", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        bundle = json.loads(args.input.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EX_NOINPUT
    if not isinstance(bundle, dict):
        print("error: input must be a JSON object", file=sys.stderr)
        return EX_NOINPUT
    result = normalize(bundle)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"output_digest": result["output_digest"], "blocking": result["blocking"], "contradictions": len(result["contradictions"])}, sort_keys=True))
    return 2 if result["blocking"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
