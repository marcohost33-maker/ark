# ARK — SOURCES & Provenance (2026-06-02)

**Projekt:** ARK-Core (Evidence Bundles / Archive-Transfer-Kernel), Coworker-Research Säule 2/Governance.
**Typ:** Code-Repo-Kandidat. **Stand:** v1.0.5 (Freeze, Code-Datum 2026-03-11).

## Kanonische Quelle (SHA-dedupliziert)
| Datei | Drive-Ort | SHA-256 (kurz) | Größe |
|---|---|---|---|
| `ARK-Core_v1.0.5_freeze.zip` | `G:\…\0Forschung Coworkerz\` | `3f515f305ce69492…` | 19062 B |

**Dedup:** 3 byte-identische Kopien gefunden (`ARK-Core_v1.0.5_freeze.zip`, `…(1).5…`, `…(2).5…`) —
alle SHA `3f515f30…`. **Eine** übernommen, 2 verworfen.
TOC ebenfalls 3 Kopien (`TOC_ARK-Core_v1.0.5.md` + (1)/(2)) → eine.

## Inhalt (extrahiert nach `extracted/ARK-Core_v1.0.5_freeze/`)
- `SCHEMAS/` — 4 JSON-Schemas (gate_report, prov_min, report_evidence_profile, testvector)
- `SPECS/` — 14 Spec-Markdowns (Archive-Conformance, Baseline-Policy, Hysteresis-FSM, Provenance-Minimal, …)
- `TOOLS/` — **6 Python-Tools** (contradiction_rules, event_hysteresis, provenance_validate, root_finding, severity_mapping, validate_run)
- `TESTVECTORS/` — baseline/report/severity JSON
- `artifacts/FREEZE_MANIFEST_v1.0.5.json` (SHA-256 je Datei), `docs/architecture_overview.md`, `README.md`, `tocs/`

## Offen vor Repo-Init (Workflow Phase 4-5)
- [ ] Verify-Gate: TOOLS/*.py importierbar/lauffähig? (Smoke-Test)
- [ ] Standard-Dateien ergänzen: LICENSE (Apache-2.0), AGENTS.md/CLAUDE.md (Tier-1, gehärtete Secrets-Zeile), CITATION.cff, .gitignore, .github/workflows/ci.yml
- [ ] `gh repo create marcohost33-maker/ARK --private`

*Vero | 2026-06-02 | ARK SOURCES | Quelle Drive-verifiziert, SHA-dedupliziert*
