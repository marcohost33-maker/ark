# REPORTING_POLICY_v1
Version: 1.1.0
Status: DRAFT

Required outputs:
- reports/gate_report.json
- optional reports/evidence_profile.json when status != ACCEPT

Reports must be self-validated against JSON Schema before a run is considered finalized.

CLI exit codes (validate_run):
- Default: 0 whenever a report was written, whatever its status; 1 when the policy cannot
  be established (REJECT report with NEG.POLICY.UNREADABLE is still written), the report
  cannot be written, or the validator fails internally (no report); 2 on a command-line
  usage error.
- Whenever no report is written, an older report at the output path is removed where the
  file system allows it, so a stale verdict is never left behind silently.
- Opt-in `--strict-exit` (issue #37): the exit code carries the verdict.
  - 0 = ACCEPT or ACCEPT_WITH_NOTES
  - 1 = REJECT
  - 2 = tool error: policy not established (report still written, fail-closed), report not
    writable, internal failure (no report), or a command-line usage error (argparse's own code)
  - 3 = REVIEW
- Any status outside the gate_report status enum maps to 1 (fail-closed).
- Golden vectors: TESTVECTORS/exit/*.json (`expected.outputs.strict_exit`).
