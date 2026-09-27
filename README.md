# ARK-Core

**Audit & Research Kernel — Core.** Ein globaler Audit-, Provenance-, Validierungs-, Event-, Metrik-,
Contradiction- und Governance-Kernel für **reproduzierbare wissenschaftliche und Engineering-Pipelines**.
Deterministische Python-Tools + JSON-Schemas. Coworker-Research Governance-Stack (Säule 2/4).

**Status:** v1.0.5 (Freeze). Gepusht, CI grün — `compileall` OK, Freeze-Manifest-Gate (NG-002) in sync, `ruff check .` clean, `pytest` 131/131 PASS (verifiziert 2026-09-27).

## Inhalt
- `SCHEMAS/` — 4 JSON-Schemas (gate_report, prov_min, report_evidence_profile, testvector).
- `SPECS/` — 14 Spezifikationen (Archive-Conformance, Baseline-Policy, Hysteresis-FSM, Provenance-Minimal,
  Contradiction-Rules-DSL, Reporting-Policy, Strict-JSON-Schema-Hardening, …).
- `docs/API.md` — Ein-/Ausgabe-Verträge aller Tools.
- `TOOLS/` — 6 deterministische Python-Validatoren: `validate_run`, `provenance_validate`,
  `event_hysteresis`, `severity_mapping`, `root_finding`, `contradiction_rules`;
  plus `freeze_manifest` (Integritäts-Tool, NG-002-Gate).
- `TESTVECTORS/` — baseline/report/severity-Testfälle.
- `artifacts/FREEZE_MANIFEST_v1.0.5.json` — SHA-256 je Datei (Integritäts-Anker).

## Quickstart
```bash
python TOOLS/validate_run.py --help
```

## Provenance
Quelle + SHA-Dedup-Record: siehe `SOURCES.md`. Herkunft: Coworker-Research Drive
(`ARK-Core_v1.0.5_freeze.zip`, SHA `3f515f30…`, 3 identische Kopien → eine übernommen).

## Lizenz
Apache-2.0. Attribution: Coworker Research / Coworkerz (keine Einzelnamen).
