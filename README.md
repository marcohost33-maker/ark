# ARK-Core

**Audit & Research Kernel — Core.** Ein globaler Audit-, Provenance-, Validierungs-, Event-, Metrik-,
Contradiction- und Governance-Kernel für **reproduzierbare wissenschaftliche und Engineering-Pipelines**.
Deterministische Python-Tools + JSON-Schemas. Coworker-Research Governance-Stack (Säule 2/4).

**Status:** v1.0.5 (Freeze). Gepusht, CI grün — `compileall` OK, Freeze-Manifest-Gate (NG-002) in sync, `ruff check .` clean, `pytest` 416 passed / 1 skipped (Skip nur als root: 0444-Datei bleibt schreibbar; verifiziert lokal 2026-11-18, Python 3.13 venv, hash-verifiziert aus `requirements-ci.txt`, ruff 0.15.18).

## Inhalt
- `SCHEMAS/` — 4 JSON-Schemas (gate_report, prov_min, report_evidence_profile, testvector).
- `SPECS/` — 15 Spezifikationen (Archive-Conformance, Baseline-Policy, Hysteresis-FSM, Provenance-Minimal,
  Contradiction-Rules-DSL, Reporting-Policy, Strict-JSON-Schema-Hardening, …).
- `docs/API.md` — Ein-/Ausgabe-Verträge aller Tools.
- `TOOLS/` — 6 deterministische Python-Validatoren: `validate_run`, `provenance_validate`,
  `event_hysteresis`, `severity_mapping`, `root_finding`, `contradiction_rules`;
  plus `freeze_manifest` (Integritäts-Tool, NG-002-Gate), `release_gate` + `ark_semver` (Tag-/SemVer-Gate)
  `release_sbom` (Runtime- + Build-SBOM, ARK-R8-002) und `release_bundle` (Release-Bundle =
  attestiertes Software-Subject, Closed-World-Verifier, ARK-R8-001).
- `requirements-runtime.txt` / `requirements-ci.txt` — Hash-Locks (sha256 je Artefakt), erzeugt aus
  `requirements-*.in`; installiert nur mit `--require-hashes` (Ablauf: `docs/RELEASE_HARDENING.md` §4).
- `TESTVECTORS/` — baseline/report/severity-Testfälle.
- `artifacts/FREEZE_MANIFEST_v1.0.5.json` — SHA-256 je Datei (Integritäts-Anker).
- `artifacts/RELEASE_BUNDLE_v1.0.5.sha256` — gepinnter SHA-256 des Release-Bundles
  `ARK-Core_v1.0.5_freeze.tar` (bytegleich auf Linux/Windows/macOS; `docs/RELEASE_HARDENING.md` §3a).
- `VERSION` — einzige Quelle der Release-Version; Regeln in `SPECS/VERSIONING_POLICY_v1.md`.

## Quickstart
```bash
python TOOLS/validate_run.py --help
# Release-Bundle bauen (nur wenn es dem gepinnten Digest entspricht) und als Konsument prüfen:
python TOOLS/release_bundle.py --out dist
python TOOLS/release_bundle.py --verify dist/ARK-Core_v1.0.5_freeze.tar --extract ./unpacked
```

## Provenance
Quelle + SHA-Dedup-Record: siehe `SOURCES.md`. Herkunft: Coworker-Research Drive
(`ARK-Core_v1.0.5_freeze.zip`, SHA `3f515f30…`, 3 identische Kopien → eine übernommen).

## Lizenz
Apache-2.0. Attribution: Coworker Research / Coworkerz (keine Einzelnamen).
