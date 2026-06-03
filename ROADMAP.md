# ARK-Core — Roadmap

> Initial-Draft (2026-06-02). Abgeleitet aus dem aktuellen Freeze-Stand v1.0.5.
> Reihenfolge = Vorschlag, nicht Zusage. Richtung entscheidet Coworker-Research.

## Stand
- **v1.0.5 (Freeze):** 4 JSON-Schemas, 14 Specs, 6 deterministische Python-Validatoren,
  Testvektoren, `FREEZE_MANIFEST_v1.0.5.json` (SHA-256 je Datei). 6/6 Tools `py_compile` OK.

## Phase 1 — Repo-Init & CI-Härtung
- [ ] Initial-Push (`--private`), CI grün (lint + `py_compile` aller TOOLS).
- [ ] CI erweitern: Schema-Validierung der TESTVECTORS gegen SCHEMAS bei jedem Push.
- [ ] `pytest`-Smoke je Validator (mind. 1 Positiv- + 1 Negativ-Testvektor pro Tool).

## Phase 2 — Provenance & Integrität
- [ ] Freeze-Manifest-Check als CI-Gate (Datei-SHA gegen Manifest verifizieren).
- [ ] Provenance-Minimal-Spec gegen einen echten End-to-End-Pipeline-Lauf prüfen.

## Phase 3 — Konsumierbarkeit
- [ ] `examples/` mit lauffähigem Minimal-Pipeline-Run (validate_run → provenance → report).
- [ ] API-Doku der 6 Validatoren (Ein-/Ausgabe-Verträge) in `docs/`.

## Offen / zu entscheiden
- Versionierungs-Politik nach Freeze (SemVer? Schema-Version getrennt von Tool-Version?).
- Verhältnis zu den übrigen Governance-Stack-Säulen (Cross-Referenz-Specs).
