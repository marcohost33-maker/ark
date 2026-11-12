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
3. build artifacts via `TOOLS/release_sbom.py --out dist`: runtime SBOM
   (`dist/sbom.runtime.cdx.json`), build-environment SBOM (`dist/sbom.build.cdx.json`)
   + the freeze manifest;
4. **`actions/attest-build-provenance`** over `dist/*` → signed build-provenance
   attestation (SLSA-style), using OIDC (`id-token: write`, `attestations: write`);
5. upload `dist/` as a build artifact.

Caveat: build-provenance attestation on a **private** repository depends on the
org/repo attestation settings; on this private repo it may need enabling. The
workflow is config-ready; enabling attestation storage is a repo-settings step
(→ Vero, alongside the ruleset).

## 3. SBOM generation path

`TOOLS/release_sbom.py` produces two CycloneDX JSON SBOMs, each named for its subject
(ARK-R8-002, 2026-11-10):

| File | Subject | How |
|---|---|---|
| `sbom.runtime.cdx.json` | what the TOOLS need to **run** | fresh venv without pip, only `requirements-runtime.txt` installed; the SBOM's component set must equal the pins exactly (name + version, nothing missing, nothing extra), else exit 1 and no runtime SBOM is left behind |
| `sbom.build.cdx.json` | the release job's environment (test + SBOM tooling) | `cyclonedx-py environment` over the job interpreter |

Both use `--output-reproducible` (same environment, same bytes). `ci.yml` runs the same
script on every PR. Reason: the earlier inline call `cyclonedx-py environment --outfile ...`
was never executed before a tag and would have failed on the first one (`--outfile` is not
a cyclonedx-py option, exit 2), and its single SBOM described the build job, not the runtime.

ARK still ships **no packaged distribution** (no `pyproject.toml` / wheel); the
source-integrity artifact is the freeze manifest (SHA-256 per file). An installable,
attested software subject (ARK-R8-001) remains an owner decision; if ARK is packaged,
the runtime SBOM subject becomes the built wheel/sdist.

## 4. Dependency pinning / lock strategy (hash locks)

Every `pip install` in CI and release verifies artifact digests (OpenSSF Scorecard
*Pinned-Dependencies*; 2026-11-10):

| Input (edit by hand) | Hash lock (generated, committed) | Used by |
|---|---|---|
| `requirements-runtime.in` — direct runtime deps of `TOOLS/`, exact pins | `requirements-runtime.txt` — full closure, no markers | `release_sbom.py` runtime venv |
| `requirements-ci.in` — runtime + `ruff`, `pytest`, `cyclonedx-bom` | `requirements-ci.txt` — full closure, universal markers | `ci.yml`, `release.yml` |

- Install: `python -m pip install --require-hashes --only-binary=:all: -r requirements-ci.txt`.
  `--require-hashes`: every artifact must match a recorded sha256, and every
  dependency must be in the lock (an unlocked transitive dependency is an install
  error). `--only-binary=:all:`: no sdist build code runs. The runner's bundled pip is
  used as is (no unpinned `pip install --upgrade pip`); pip >= 22.3 is required for
  `pip --python`.
- Re-lock after editing an `.in` file (the exact command is also in each lock header):

  ```sh
  uv pip compile requirements-runtime.in --universal --python-version 3.12 --generate-hashes -o requirements-runtime.txt
  uv pip compile requirements-ci.in -c requirements-runtime.txt --universal --python-version 3.12 --generate-hashes -o requirements-ci.txt
  python TOOLS/freeze_manifest.py --regenerate
  ```

  The CI lock is constrained by the runtime lock, so the tests run on exactly the
  artifacts the runtime SBOM attests. `uv` is only needed to re-lock, never in CI.
- Why not PEP 751 `pylock.toml`: pip's support (26.1) is explicitly experimental and may
  change without notice; a determinism kernel waits for it to stabilize.
- Guarded by `tests/test_release_sbom.py`: locks parse as exact hashed pins (runtime lock
  marker-free), CI lock holds the runtime closure byte-for-byte (version + sha256 set),
  each lock is fresh for its `.in`, every workflow `pip install` uses `--require-hashes`,
  every third-party import in `TOOLS/` has a runtime pin.

GitHub Actions are managed by Dependabot (`.github/dependabot.yml`, weekly,
7-day cooldown, SHA-pin preserving). Python locks are re-locked deliberately (above);
Dependabot does not manage them.

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
python -m pip install --require-hashes --only-binary=:all: -r requirements-ci.txt --dry-run

# Release SBOM path (expected: 'sbom.runtime.cdx.json matches ...', exit 0):
python TOOLS/release_sbom.py --out /tmp/ark-sbom

# Freeze integrity (expected: 'freeze manifest in sync', exit 0):
python TOOLS/freeze_manifest.py
```

## Boundary

Delivered here: workflow files + pinning + SBOM path + attestation design +
ruleset spec + evidence commands. **Deferred to Vero:** applying the branch
ruleset and enabling attestation storage (privileged repo-settings actions).
