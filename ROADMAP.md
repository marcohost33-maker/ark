# ARK-Core — Roadmap

> Initial-Draft (2026-06-02), Stand aktualisiert 2026-06-30. Abgeleitet aus dem Freeze-Stand v1.0.5.
> Reihenfolge = Vorschlag, nicht Zusage. Richtung entscheidet Coworker-Research.

## Stand
- **v1.0.5 (Freeze):** 4 JSON-Schemas, 14 Specs, 6 deterministische Python-Validatoren
  (`validate_run`, `provenance_validate`, `event_hysteresis`, `severity_mapping`,
  `root_finding`, `contradiction_rules`) + 1 Integritäts-Tool (`freeze_manifest`),
  Testvektoren, `FREEZE_MANIFEST_v1.0.5.json` (SHA-256 je Datei, 36 Dateien gepinnt).
- **CI-Gates aktiv (verifiziert 2026-06-30):** `ruff --select=F,E9` clean · `compileall`
  aller TOOLS/tests · Freeze-Manifest-Gate (NG-002, fail-closed) · `pytest` **34/34 PASS** ·
  zizmor Workflow-Audit (required) · Dependabot (github-actions, weekly, SHA-Pins).

## Phase 1 — Repo-Init & CI-Härtung
- [x] Initial-Push, CI grün (`ruff F,E9` + `compileall` aller TOOLS/tests). _(verifiziert 2026-06-30)_
- [ ] CI erweitern: Schema-Validierung der TESTVECTORS gegen SCHEMAS bei jedem Push.
- [~] `pytest`-Smoke je Validator: 34 Tests grün (Import-Smoke aller 6 Validatoren +
  Negativ-Fälle für `validate_run`/Freeze/SemVer). Offen: je 1 Positiv- + 1 Negativ-Testvektor **pro** Tool.

## Phase 2 — Provenance & Integrität
- [x] Freeze-Manifest-Check als CI-Gate (Datei-SHA gegen Manifest verifizieren). _(NG-002 enforced, PR #8)_
- [ ] Provenance-Minimal-Spec gegen einen echten End-to-End-Pipeline-Lauf prüfen.

## Phase 3 — Konsumierbarkeit
- [ ] `examples/` mit lauffähigem Minimal-Pipeline-Run (validate_run → provenance → report).
- [ ] API-Doku der 6 Validatoren (Ein-/Ausgabe-Verträge) in `docs/`.

## Offen / zu entscheiden
- Versionierungs-Politik nach Freeze (SemVer? Schema-Version getrennt von Tool-Version?).
- Verhältnis zu den übrigen Governance-Stack-Säulen (Cross-Referenz-Specs).
