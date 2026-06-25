#!/usr/bin/env python3
import json, os, re
from datetime import datetime, timezone
from jsonschema import validate as jsonschema_validate, ValidationError
from severity_mapping import classify_neg_id

# Official SemVer 2.0.0 regex (semver.org, "Backus-Naur Form Grammar" appendix).
# Forbids leading zeros in numeric prerelease identifiers and empty identifiers,
# which the previous pattern wrongly accepted (e.g. 1.2.3-0123, 1.0.0-alpha..).
SEMVER_RE = re.compile(
    r"^(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)"
    r"(?:-(?P<prerelease>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)"
    r"(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    r"(?:\+(?P<buildmetadata>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"
)
ROOT_ALLOWED_METHODS = {"bisect", "brentq", "brenth", "ridder", "toms748"}

def utc_now():
    return datetime.now(timezone.utc).isoformat()

def read_json(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def validate_json_against_schema(instance, schema_path):
    schema = read_json(schema_path)
    jsonschema_validate(instance=instance, schema=schema)

def check_root_policy(policy):
    method = policy.get("ROOT", {}).get("METHOD", "brentq")
    return [] if method in ROOT_ALLOWED_METHODS else ["NEG.ROOT.UNKNOWN_METHOD"]

def check_kernel_files(run_dir):
    req = ["kernel.model.json","kernel.plan.json","kernel.events.json","kernel.schema.json","kernel.env.json"]
    neg=[]
    for f in req:
        if not os.path.exists(os.path.join(run_dir,"kernels",f)):
            neg.append("NEG.KERNEL.MISSING_" + f.split('.')[1].upper())
    return neg

def check_kernel_payload(obj):
    neg=[]
    if not obj.get("content_hash"): neg.append("NEG.KERNEL.MISSING_HASH")
    if not obj.get("version"): neg.append("NEG.KERNEL.MISSING_VERSION")
    elif not SEMVER_RE.match(obj["version"]): neg.append("NEG.KERNEL.INVALID_SEMVER")
    if "payload" not in obj: neg.append("NEG.KERNEL.MISSING_PAYLOAD")
    return neg

def validate_run(run_dir):
    policy = {}
    hard_fail=[]; soft_fail=[]; warnings=[]; known_issues=[]
    report = {
        "run_id": os.path.basename(run_dir.rstrip('/')),
        "created_utc": utc_now(),
        "status": "ACCEPT",
        "hard_fail": hard_fail,
        "soft_fail": soft_fail,
        "warnings": warnings,
        "known_issues": known_issues,
        "metrics": [],
        "gate_results": []
    }
    hard_fail.extend(check_kernel_files(run_dir))
    kernels_dir=os.path.join(run_dir,'kernels')
    if os.path.isdir(kernels_dir):
        for fn in os.listdir(kernels_dir):
            if fn.startswith('kernel.') and fn.endswith('.json'):
                obj = read_json(os.path.join(kernels_dir, fn))
                hard_fail.extend([n for n in check_kernel_payload(obj) if classify_neg_id(n, policy)=="HARD_FAIL"])
    for n in check_root_policy(policy):
        if classify_neg_id(n, policy)=="HARD_FAIL": hard_fail.append(n)
        else: soft_fail.append(n)
    if hard_fail: report["status"] = "REJECT"
    elif soft_fail: report["status"] = "REVIEW"
    elif warnings or known_issues: report["status"] = "ACCEPT_WITH_NOTES"
    try:
        validate_json_against_schema(report, os.path.join(os.path.dirname(__file__), '..', 'SCHEMAS', 'gate_report.schema.json'))
    except ValidationError:
        report["status"] = "REJECT"
        report["hard_fail"].append("NEG.REPORT.SCHEMA_INVALID")
    return report

if __name__ == '__main__':
    import argparse
    ap=argparse.ArgumentParser(); ap.add_argument('--run', required=True); ap.add_argument('--out', default=None)
    args=ap.parse_args(); report=validate_run(args.run)
    out=args.out or os.path.join(args.run,'reports','gate_report.json'); os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out,'w',encoding='utf-8') as f: json.dump(report,f,indent=2,sort_keys=True)
    print(out)
