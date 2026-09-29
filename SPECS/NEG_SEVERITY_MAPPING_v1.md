# NEG_SEVERITY_MAPPING_v1
Version: 1.0.5
Status: DRAFT

Central mapping from NEG IDs to severity:
- HARD_FAIL
- SOFT_FAIL
- WARNING
- KNOWN_ISSUE
- WAIVED_ISSUE

Unknown NEG IDs are errors by themselves.

## Policy levers and non-downgradable IDs (clarification, hardening wave 2)
A policy can soften a NEG ID through three levers: `severity_overrides`,
`known_issues` (-> KNOWN_ISSUE) and `waivers` (-> WAIVED_ISSUE). All three are
downgrades. Non-downgradable IDs — the NON_DOWNGRADABLE set plus every
`NEG.KERNEL.*` ID (kernel integrity) — are immune to every lever: they keep
their mapped severity, and a policy that names one of them in any lever is
rejected as malformed (fail-closed). Override values must be one of
HARD_FAIL, SOFT_FAIL, WARNING.

## NEG.POLICY.UNREADABLE (clarification, issue #33)
When the effective policy cannot be established -- policy file missing,
unreadable or malformed, or the run directory cannot be listed so the presence
of a `policy.json` cannot be decided -- the run-gate CLI reports REJECT with
`NEG.POLICY.UNREADABLE`. The ID is HARD_FAIL and non-downgradable: no policy can
waive the absence of a readable policy.
