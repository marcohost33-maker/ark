# ARK-Core — Roadmap

> Initial-Draft (2026-06-02), Stand aktualisiert 2026-10-19. Abgeleitet aus dem Freeze-Stand v1.0.5.
> Reihenfolge = Vorschlag, nicht Zusage. Richtung entscheidet Coworker-Research.

## Stand
- **v1.0.5 (Freeze):** 4 JSON-Schemas, 14 Specs, 6 deterministische Python-Validatoren
  (`validate_run`, `provenance_validate`, `event_hysteresis`, `severity_mapping`,
  `root_finding`, `contradiction_rules`) + 1 Integritäts-Tool (`freeze_manifest`),
  Testvektoren, `FREEZE_MANIFEST_v1.0.5.json` (SHA-256 je Datei, 71 Dateien gepinnt, Stand 2026-10-19).
- **CI-Gates aktiv (verifiziert 2026-09-28; Zählung lokal 2026-10-19):** `ruff check .` clean · `compileall`
  aller TOOLS/tests · Freeze-Manifest-Gate (NG-002, fail-closed) · `pytest` **237 passed / 1 skipped** (lokal 2026-10-19) ·
  zizmor Workflow-Audit (required) · Dependabot (github-actions, weekly, SHA-Pins).

## Phase 1 — Repo-Init & CI-Härtung
- [x] Initial-Push, CI grün (`ruff F,E9` + `compileall` aller TOOLS/tests). _(verifiziert 2026-06-30)_
- [x] CI erweitern: Schema-Validierung der TESTVECTORS gegen SCHEMAS bei jedem Push. _(PR #20, `tests/test_schema_fixtures.py`)_
- [x] `ruff check .` (DoD) statt nur `F,E9` als CI-Gate; 13 E70x-Befunde in `TOOLS/` behoben. _(Hardening-Welle 2)_
- [x] `pytest`-Smoke je Validator + je 1 Positiv- + 1 Negativ-Behavioral-Testvektor **pro** Tool
  (`tests/test_tool_behaviors.py` + `TESTVECTORS/{provenance,severity,contradiction}/`). _(issue #16)_

## Phase 2 — Provenance & Integrität
- [x] Freeze-Manifest-Check als CI-Gate (Datei-SHA gegen Manifest verifizieren). _(NG-002 enforced, PR #8)_
- [x] Provenance-Minimal-Spec gegen einen echten End-to-End-Pipeline-Lauf geprüft (`examples/minimal_run`). _(issue #17)_
- [x] Explizites Policy-Laden + `format: date-time`-Enforcement in `validate_run.py`. _(issue #18, `docs/POLICY_LOADING.md`)_

## Phase 3 — Konsumierbarkeit
- [x] `examples/` mit lauffähigem Minimal-Pipeline-Run (validate_run → provenance → report). _(issue #17)_
- [x] Release-Härtung: Release-Workflow + SBOM + Attestation-Design + Dependency-Pinning. _(issue #19, `docs/RELEASE_HARDENING.md`)_
- [x] API-Doku der Validatoren (Ein-/Ausgabe-Verträge) in `docs/API.md`. _(Hardening-Welle 2)_

## Phase 2b — Spec-vs-Code-Härtung (Hardening-Welle 2)
- [x] NON_DOWNGRADABLE-IDs gegen **alle** Policy-Hebel gesperrt (Waiver/Known-Issue waren ein Bypass).
- [x] Kaputtes Kernel-JSON -> `NEG.KERNEL.UNREADABLE` (REJECT mit Report statt Absturz), auch bei Int-Ziffernlimit (`ValueError`), Verschachtelung über das Rekursionslimit (`RecursionError`) und nicht listbarem `kernels/`.
- [x] Kernel-Dateinamen exakt (case-sensitiv) gegen die `os.listdir`-Menge statt `os.path.exists`: `kernel.PLAN.json` wurde auf Windows/macOS als vorhandener Plan gezählt, ohne dass die Root-Methode geprüft wurde. Neu `NEG.KERNEL.NAME_CASE_MISMATCH` (HARD); Urteil unabhängig vom Dateisystem.
- [x] Contradiction-DSL: Ganzbaum-Strukturprüfung (kein Crash, kein Short-Circuit-Schlupfloch, JSON-bool ist keine Zahl).
- [x] Provenance: `used`/`wasDerivedFrom` referenzgeprüft in PROV-DM-Richtung; `UNKNOWN_EDGE_TYPE`, `DUPLICATE_ID`, `MISSING_ID`.
- [x] Hysterese: `delta >= 0`, `min_support >= 1`, `min_duration >= 0` erzwungen.
- [x] Root-Methode aus `kernel.plan.json` (`payload.root.METHOD`) statt totem Policy-Pfad: `NEG.ROOT.UNKNOWN_METHOD` ist wieder erreichbar.
- [x] `NEG.KERNEL.*` non-downgradable (Kernel-Integrität = Reproduzierbarkeits-Anker).
- [x] Nicht ladbare Policy / nicht listbares Run-Verzeichnis: CLI schreibt REJECT-Report mit `NEG.POLICY.UNREADABLE` (HARD, non-downgradable), Exit 1, alter Report wird ersetzt. _(#33)_
- [x] `run_id` unabhängig vom Pfad-Trenner am Ende (`run\` auf Windows). _(#34)_
- [x] Opt-in `--strict-exit`: Exitcode trägt das Verdikt (0 ACCEPT/ACCEPT_WITH_NOTES, 1 REJECT, 2 Werkzeugfehler = argparse-Usage-Code, 3 REVIEW); Default unverändert. _(#37)_

## Offen / zu entscheiden
- `--strict-exit` als Default (#37, Schritt 2): erst wenn alle Aufrufer (CI, USK-Adapter, Skripte) migriert sind; offen, ob REVIEW CI rot färben soll.
- Versionierungs-Politik nach Freeze (SemVer? Schema-Version getrennt von Tool-Version?).
- Verhältnis zu den übrigen Governance-Stack-Säulen (Cross-Referenz-Specs).
