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
3. build artifacts into `dist/`: runtime SBOM (`sbom.runtime.cdx.json`) and
   build-environment SBOM (`sbom.build.cdx.json`) via `TOOLS/release_sbom.py`; the
   **release bundle** `ARK-Core_v<VERSION>_freeze.tar` via `TOOLS/release_bundle.py`
   (the software subject, section 3a); the freeze manifest, the bundle digest pin and
   `VERSION`;
4. **`actions/attest-build-provenance`** over `dist/*` → signed build-provenance
   attestation (SLSA-style), using OIDC (`id-token: write`, `attestations: write`).
   Every file in `dist/` is a subject, so the attestation names the bundle's SHA-256;
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

## 3a. Release bundle: the software subject (ARK-R8-001, ARK-R8-004)

Before 2026-11-18 the release job attested metadata only (SBOMs, manifest, `VERSION`); no
attested digest named the software a consumer runs (cross-family review R8, re-confirmed
in the R4 re-audit of 2026-11-10). `TOOLS/release_bundle.py` adds that subject. Contract:
`SPECS/ARCHIVE_CONFORMANCE_v1.md`, "Release bundle".

| Property | How |
|---|---|
| Content | exactly the files pinned by the freeze manifest + the manifest, under `ARK-Core_v<VERSION>_freeze/`; same layout as the repository, so `python TOOLS/validate_run.py` works as documented |
| Reproducible | one canonical uncompressed ustar encoding with fixed metadata; no clock, env var, umask or zlib version enters the bytes; Linux, Windows and macOS build the identical file |
| Reviewed digest | `artifacts/RELEASE_BUNDLE_v<VERSION>.sha256` is committed; `ci.yml` (all four platform jobs) and `release.yml` refuse a build that does not equal it |
| Closed world | `--verify` accepts only the canonical encoding of exactly the manifest's files with matching digests; links, extra or missing members, altered metadata, trailing data and unsafe paths are refused |

Why an archive of the repository layout and not a wheel: the tools are documented and consumed
as `python TOOLS/<tool>.py` with sibling imports and a relative `SCHEMAS/` lookup. A wheel needs
an importable package name and layout (a public-surface decision, MAJOR under the versioning
policy) and a build backend in the trusted base. The bundle needs neither and uses the standard
library only. A wheel/sdist published to an index stays an owner decision; it would be an
additional subject, not a replacement.

After changing any pinned file:

```sh
python TOOLS/freeze_manifest.py --regenerate
python TOOLS/release_bundle.py --pin
```

### Consumer verification

```sh
V=1.1.0   # the release being consumed
# 1. Who built it, from which source (GitHub artifact attestation, current gh CLI):
gh attestation verify "ARK-Core_v${V}_freeze.tar" --repo marcohost33-maker/ark \
  --signer-workflow marcohost33-maker/ark/.github/workflows/release.yml \
  --source-ref "refs/tags/v${V}" --deny-self-hosted-runners
# 2. Same digest as the pin in the tagged source:
sha256sum -c "RELEASE_BUNDLE_v${V}.sha256"
# 3. Closed-world check and unpack (verifier from a checkout you already trust):
python -I -S TOOLS/release_bundle.py --verify "ARK-Core_v${V}_freeze.tar" --extract ./ark
# 4. Runtime dependencies, hash-locked, then the unpacked tree checks itself:
python -m pip install --require-hashes --only-binary=:all: -r "ark/ARK-Core_v${V}_freeze/requirements-runtime.txt"
python "ark/ARK-Core_v${V}_freeze/TOOLS/freeze_manifest.py"
```

Limits (stated, not solved here):
- Step 3 proves the bundle is canonical and consistent with its own manifest, not who made
  it. Authenticity rests on step 1 (or on a digest obtained from a trusted channel).
- No tag has been pushed yet, so step 1 has never run against a real attestation; the first
  release must exercise it, including a negative probe (wrong repo, wrong ref, altered byte).
- On a private repository, attestation storage depends on the plan/settings (section 2).
- The verifier bootstraps from somewhere: a trusted checkout, or the bundle's own copy
  after step 1 has established the bundle's origin.
- Independent witness and the DDE→ARK→USK consumer receipt (ARK-R8-005) are separate work.

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

# Release bundle equals the committed pin (expected: 'release bundle: <sha256>  ARK-Core_v...tar', exit 0):
python TOOLS/release_bundle.py --out /tmp/ark-bundle
```

## Boundary

Delivered here: workflow files + pinning + SBOM path + release bundle (software
subject, closed-world verifier, digest pin) + attestation design + ruleset spec +
evidence commands. **Deferred to Vero:** applying the branch
ruleset and enabling attestation storage (privileged repo-settings actions).
