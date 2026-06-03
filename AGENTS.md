---
format: agents.md
version: "1.0"
project: ARK-Core
---

# AGENTS.md — ARK-Core

KI-Coding-Agent-Anweisungen für dieses Repo. Reihenfolge: §1 Working agreements > §2 Conventions >
§3 Don't > §4 When stuck.

## Project
- **Was:** Audit & Research Kernel — Core: Audit/Provenance/Validierung/Event/Metrik/Contradiction/Governance-Kernel für reproduzierbare Pipelines (deterministisch, stdlib-orientiert).
- **Stack:** Python ≥3.10. Schemas = JSON Schema. Keine ML in Validierungs-Entscheidungspfaden.
- **Version:** 1.0.5 (Freeze, siehe `artifacts/FREEZE_MANIFEST_v1.0.5.json`).

## Working agreements
1. **Determinismus ist tragend.** Validatoren müssen reproduzierbar dasselbe Urteil liefern; keine
   Zufalls-/ML-Pfade in `TOOLS/`.
2. **Freeze-Manifest ist die Integritäts-Wahrheit.** Datei-Änderung → Manifest-SHA mit-aktualisieren.
3. **Reality-Anchor.** „Tests N/N PASS (verified <date>)" statt „sollte gehen".

## Conventions
- Tests neben Änderungen; Testvektoren in `TESTVECTORS/` pflegen.
- Specs in `SPECS/` sind die Vertrags-Quelle; Code folgt der Spec, nicht umgekehrt.

## Don't
- Don't merge mit `ruff`/`pytest` rot.
- Don't use `--no-verify`, `--no-gpg-sign`, `--force` ohne explizites User1-OK.
- Don't commit or leak secrets, API keys, `.env`/credential files, `GITHUB_TOKEN`, or signing keys (logs included).
- Don't ML/Heuristik in deterministische Validierungs-Entscheidungen einbauen.

## When stuck
- `docs/architecture_overview.md` + `SPECS/`. Nach 3 Fehlversuchen: Draft-PR mit Evidenz statt Loop.

## Definition of Done
| # | Check | Evidence |
|---|---|---|
| 1 | `ruff check .` clean | CI |
| 2 | `pytest -q` grün | CI |
| 3 | Freeze-Manifest konsistent | manual |
| 4 | Neue Behaviour hat Test (fails-before/passes-after) | review |

---
*Coworker Research. Format: <https://agents.md/>.*
