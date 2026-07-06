# Release & governance hardening (issue #19)

Scope: release/governance hardening only — not validator behavior. This
document is the design + evidence surface; the executable pieces are
`.github/workflows/release.yml`, `requirements-ci.txt`, and the existing
`.github/workflows/zizmor.yml` + `.github/dependabot.yml`.

## 1. Branch ruleset for `main` — DESIGN (config action → Vero)

> **NOT applied by this PR.** Repository ruleset / branch-protection changes are
> made by Vero via `gh api`, per the split-of-powers rule. This section is the
> spec for that change.

Required ruleset for `main`:

| Requirement | Setting |
|---|---|
| Pull request required | `required_pull_request_reviews`, ≥1 approval, dismiss stale approvals |
| Conversation resolution | `required_conversation_resolution: true` |
| Required status checks | contexts: **`gate`** (ci.yml), **`zizmor workflow audit`** (zizmor.yml) |
| Strict / up-to-date | `strict: true` (branch must be current with `main` before merge) |
| No direct pushes | `restrictions` / block force-push + require PR (no bypass for non-owners) |
| Linear history | recommended `required_linear_history: true` (squash merges) |

Suggested `gh` command (for Vero to run — illustrative, verify before applying):

```sh
gh api -X PUT repos/marcohost33-maker/ark/branches/main/protection \
  -F required_pull_request_reviews.required_approving_review_count=1 \
  -F required_conversation_resolution.enabled=true \
  -F 'required_status_checks.contexts[]=gate' \
  -F 'required_status_checks.contexts[]=zizmor workflow audit' \
  -F required_status_checks.strict=true \
  -F enforce_admins=false -F restrictions=
```

Evidence after apply: `gh api repos/marcohost33-maker/ark/branches/main/protection`.

## 2. Release workflow + attestation

`.github/workflows/release.yml` triggers on `v*.*.*` tags (and manual dispatch).
It does **not** run on ordinary PRs, so it never gates feature work. Steps:

1. checkout (SHA-pinned, `persist-credentials: false`);
2. freeze-manifest gate (`TOOLS/freeze_manifest.py`) — release must be in sync;
3. build artifacts: CycloneDX SBOM (`dist/sbom.cdx.json`) + the freeze manifest;
4. **`actions/attest-build-provenance`** over `dist/*` → signed build-provenance
   attestation (SLSA-style), using OIDC (`id-token: write`, `attestations: write`);
5. upload `dist/` as a build artifact.

Caveat: build-provenance attestation on a **private** repository depends on the
org/repo attestation settings; on this private repo it may need enabling. The
workflow is config-ready; enabling attestation storage is a repo-settings step
(→ Vero, alongside the ruleset).

## 3. SBOM generation path

An SBOM is produced by `cyclonedx-py environment` (CycloneDX JSON) over the
pinned release environment. ARK ships **no packaged distribution** (no
`pyproject.toml` / wheel), so the SBOM documents the *tooling/runtime*
dependency set rather than a package's transitive tree; the source-integrity
artifact is the freeze manifest (SHA-256 per file). If ARK is later packaged,
switch the SBOM subject to the built wheel/sdist and attest that instead.

## 4. Dependency pinning / lock strategy

`requirements-ci.txt` pins the four test dependencies to exact versions
(`ruff`, `pytest`, `jsonschema`, `scipy`), all compatible with the CI Python
matrix (>=3.11). Both `ci.yml` and `release.yml` install from it — one
reviewable choke point. `cyclonedx-bom` is pinned inline in `release.yml`.
GitHub Actions are managed by Dependabot (`.github/dependabot.yml`, weekly,
7-day cooldown, SHA-pin preserving).

## 5. Actions pinned to immutable SHAs + audit

Every `uses:` across `ci.yml`, `zizmor.yml`, `release.yml` is pinned to a
40-char commit SHA (tag in a trailing comment). `zizmor` runs on every PR as the
**required** `zizmor workflow audit` check and fails closed on findings
(including unpinned actions).

## 6. Evidence commands & expected outputs

```sh
# All actions SHA-pinned (expected: no bare tags on `uses:`):
grep -rEn "uses:" .github/workflows | grep -vE "@[0-9a-f]{40}" || echo "all pinned"

# Pinned test deps resolvable (expected: exit 0):
python -m pip install -r requirements-ci.txt --dry-run

# Freeze integrity (expected: 'freeze manifest in sync', exit 0):
python TOOLS/freeze_manifest.py
```

## Boundary

Delivered here: workflow files + pinning + SBOM path + attestation design +
ruleset spec + evidence commands. **Deferred to Vero:** applying the branch
ruleset and enabling attestation storage (privileged repo-settings actions).
