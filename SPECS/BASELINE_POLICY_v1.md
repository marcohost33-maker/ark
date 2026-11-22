# BASELINE_POLICY_v1
Version: 1.1.0
Status: DRAFT

Baselines are explicit artifacts stored as `kernel.baseline.json`.

Required fields:
- baseline_id
- baseline_type (run-local|release|project|gold-standard)
- baseline_scope
- baseline_version
- metric_snapshot
- selection_policy
- created_utc
- content_hash

Rules:
- no implicit baseline selection
- no in-place baseline mutation
- baseline drift requires new baseline_id or version bump
