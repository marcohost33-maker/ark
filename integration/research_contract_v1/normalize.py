from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

PROMOTED = {"PROVEN", "BENCHMARKED", "SUPPORTED", "PASS", "VERIFIED"}
PASS_EVIDENCE = {"PASS", "VERIFIED"}
EX_NOINPUT = 66


def _canon(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


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


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return []
    return [str(x) for x in value if isinstance(x, str) and x]


def _valid_sha256(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        return False
    digest = value[7:]
    return len(digest) == 64 and all(c in "0123456789abcdef" for c in digest)


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
    code_revision = run.get("code_revision")
    promoted = str(claim.get("status", "")).upper() in PROMOTED

    if claim_id == "<missing-claim>":
        contradictions.append(_contradiction(
            "RC.CLAIM.ID_MISSING", claim_id, "ClaimCard has no claim_id.", [claim_id]
        ))
    if run_id == "<missing-run>":
        contradictions.append(_contradiction(
            "RC.RUN.ID_MISSING", run_id, "RunPlan has no run_id.", [run_id]
        ))
    if not isinstance(code_revision, str) or len(code_revision) < 7:
        contradictions.append(_contradiction(
            "RC.RUN.REVISION_MISSING", run_id, "RunPlan has no usable code_revision.", [run_id]
        ))

    by_id: dict[str, dict[str, Any]] = {}
    duplicates: set[str] = set()
    for item in evidence:
        evidence_id = item.get("evidence_id")
        if not isinstance(evidence_id, str) or not evidence_id:
            contradictions.append(_contradiction(
                "RC.EVIDENCE.ID_MISSING", claim_id, "EvidenceAttestation has no evidence_id.", [claim_id]
            ))
            continue
        if evidence_id in by_id:
            duplicates.add(evidence_id)
        else:
            by_id[evidence_id] = item
    for evidence_id in sorted(duplicates):
        contradictions.append(_contradiction(
            "RC.EVIDENCE.DUPLICATE_ID", claim_id,
            f"Duplicate evidence_id {evidence_id} prevents unambiguous binding.",
            [claim_id, evidence_id],
        ))

    referenced = _string_list(claim.get("evidence_ids", []))
    required_provenance_fields = set(_string_list(bundle.get("provenance_fields", [])))
    required_provenance_fields.update({"material_digest", "source_revision"})

    if promoted:
        if not referenced:
            contradictions.append(_contradiction(
                "RC.EVIDENCE.NONE_REFERENCED", claim_id,
                "Promoted claim has no referenced evidence IDs.", [claim_id]
            ))
        for evid in referenced:
            item = by_id.get(evid)
            if item is None:
                contradictions.append(_contradiction(
                    "RC.EVIDENCE.MISSING", claim_id,
                    f"Promoted claim references missing evidence {evid}.", [claim_id, evid]
                ))
                continue
            subject = item.get("subject") if isinstance(item.get("subject"), Mapping) else {}
            verdict = str(item.get("verdict", "")).upper()
            if verdict not in PASS_EVIDENCE:
                contradictions.append(_contradiction(
                    "RC.EVIDENCE.NON_PASS", claim_id,
                    f"Promoted claim references evidence {evid} with verdict {item.get('verdict')!r}.",
                    [claim_id, evid],
                ))
            if item.get("stale") is not False:
                contradictions.append(_contradiction(
                    "RC.EVIDENCE.STALE", claim_id,
                    f"Promoted claim references evidence {evid} that is stale or lacks explicit freshness=false.",
                    [claim_id, evid],
                ))
            if subject.get("claim_id") != claim_id or subject.get("run_id") != run_id:
                contradictions.append(_contradiction(
                    "RC.EVIDENCE.UNBOUND", claim_id,
                    f"Evidence {evid} is not bound to claim={claim_id} and run={run_id}.",
                    [claim_id, run_id, evid],
                ))
            missing_fields = sorted(
                field for field in required_provenance_fields if not item.get(field)
            )
            if missing_fields:
                contradictions.append(_contradiction(
                    "RC.EVIDENCE.PROVENANCE_INCOMPLETE", claim_id,
                    f"Evidence {evid} lacks required provenance fields: {missing_fields}.",
                    [claim_id, evid],
                ))
            if item.get("source_revision") != code_revision:
                contradictions.append(_contradiction(
                    "RC.EVIDENCE.SOURCE_REVISION_MISMATCH", claim_id,
                    f"Evidence {evid} source_revision does not match RunPlan code_revision.",
                    [claim_id, run_id, evid],
                ))
            if not _valid_sha256(item.get("material_digest")):
                contradictions.append(_contradiction(
                    "RC.EVIDENCE.DIGEST_INVALID", claim_id,
                    f"Evidence {evid} material_digest is not a canonical sha256:<64 hex> digest.",
                    [claim_id, evid],
                ))

        required_oracles = set(_string_list(run.get("required_oracles", [])))
        covered = {
            str(x.get("oracle_id"))
            for x in evidence
            if x.get("evidence_id") in referenced
            and str(x.get("verdict", "")).upper() in PASS_EVIDENCE
            and x.get("stale") is False
            and isinstance(x.get("subject"), Mapping)
            and x["subject"].get("claim_id") == claim_id
            and x["subject"].get("run_id") == run_id
            and x.get("source_revision") == code_revision
            and _valid_sha256(x.get("material_digest"))
            and x.get("oracle_id")
        }
        for oracle in sorted(required_oracles - covered):
            contradictions.append(_contradiction(
                "RC.ORACLE.MISSING", claim_id,
                f"Required oracle {oracle} has no current passing, bound, revision-matching evidence.",
                [claim_id, run_id, oracle],
            ))

    for gate in gates:
        gate_id = str(gate.get("gate_id", "<missing-gate>"))
        if gate.get("result") == "PASS":
            if str(gate.get("subject_id")) != claim_id:
                contradictions.append(_contradiction(
                    "RC.GATE.UNBOUND", gate_id,
                    f"PASS gate does not target claim {claim_id}.", [gate_id, claim_id]
                ))
            if not _valid_sha256(gate.get("input_digest")):
                contradictions.append(_contradiction(
                    "RC.GATE.INPUT_DIGEST_INVALID", gate_id,
                    "PASS gate input_digest is missing or not a canonical SHA-256 digest.", [gate_id]
                ))
            evaluator_revision = gate.get("evaluator_revision")
            if not isinstance(evaluator_revision, str) or len(evaluator_revision) < 7:
                contradictions.append(_contradiction(
                    "RC.GATE.EVALUATOR_REVISION_MISSING", gate_id,
                    "PASS gate evaluator_revision is missing or too short.", [gate_id]
                ))

    for report in supersession:
        stale = report.get("stale_dependencies") or report.get("stale_dependency_ids") or []
        failed = report.get("result") == "FAIL" or report.get("valid") is False
        if failed:
            contradictions.append(_contradiction(
                "RC.SUPERSESSION.FAIL", _id(report),
                "Supersession report is explicitly failing.", [_id(report)]
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
                    "RC.GATE.PASS_WITH_BLOCKING_CONTRADICTION",
                    str(gate.get("gate_id", "<missing-gate>")),
                    "PASS gate targets a claim with blocking evidence contradictions.",
                    [str(gate.get("gate_id", "<missing-gate>")), claim_id],
                ))

    records.sort(key=lambda r: (r["record_type"], r["source_id"]))
    contradictions.sort(key=lambda c: (c["code"], c["subject_id"], c["detail"]))
    payload = {
        "schema_name": "ARKResearchContractNormalization",
        "schema_version": "1.1.0-candidate",
        "source": bundle.get("source", {}),
        "input_digest": _digest(bundle),
        "claim_id": claim.get("claim_id"),
        "run_id": run.get("run_id"),
        "contract_bindings": {
            "claim_card_digest": _digest(claim),
            "run_plan_digest": _digest(run),
            "code_revision": code_revision,
        },
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
    args.out.write_text(
        json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "output_digest": result["output_digest"],
        "input_digest": result["input_digest"],
        "blocking": result["blocking"],
        "contradictions": len(result["contradictions"]),
    }, sort_keys=True))
    return 2 if result["blocking"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
