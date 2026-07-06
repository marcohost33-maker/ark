# ARK-Core Architecture Overview

Flow:

Kernels -> Registry/Contracts -> Events -> Metrics -> Contradictions -> Provenance -> Gates -> Reports

Core kernels:
- kernel.model
- kernel.plan
- kernel.events
- kernel.schema
- kernel.env
- optional kernel.policy
- optional kernel.baseline
- optional kernel.known_issues
- optional kernel.registry

See also:
- `docs/POLICY_LOADING.md` — explicit policy loading + enforced `format: date-time` (issue #18).
- `docs/RELEASE_HARDENING.md` — release/governance hardening: rulesets, SBOM, attestation, pinning (issue #19).
- `examples/README.md` — minimal end-to-end pipeline run.
