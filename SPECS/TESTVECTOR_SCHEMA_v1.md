# TESTVECTOR_SCHEMA_v1
Version: 1.0.5
Status: DRAFT

Canonical shape:
{
  "name": "...",
  "inputs": {...},
  "expected": {
    "status": "ACCEPT|ACCEPT_WITH_NOTES|REVIEW|REJECT",
    "neg_ids": [...],
    "outputs": {...}
  },
  "baseline": {...},
  "policy": {...},
  "tags": [...]
}
