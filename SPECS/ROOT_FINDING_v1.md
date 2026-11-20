# ROOT_FINDING_v1
Version: 1.1.0
Status: DRAFT

Bracketed methods allowlist:
- bisect
- brentq
- brenth
- ridder
- toms748

Unknown methods are hard errors.

The method is pinned per run in `kernel.plan.json` as `payload.root.METHOD`
(REGISTRY_POLICY_v1: exact pinning in kernel.plan wins). Absent `payload.root`
selects the default `brentq`. A present entry that is not an object, or that
lacks METHOD, or whose METHOD is not an allowlisted string, raises `NEG.ROOT.UNKNOWN_METHOD`
(non-downgradable). The gate policy does not select the method.
