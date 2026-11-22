# ARK-Core — Roadmap

> Initial-Draft (2026-06-02), Stand aktualisiert 2026-11-20. Abgeleitet aus dem Freeze-Stand v1.0.5.
> Reihenfolge = Vorschlag, nicht Zusage. Richtung entscheidet Coworker-Research.

## Stand
- **v1.1.0 (Release-Kandidat, nicht getaggt; Basis: Origin-Freeze v1.0.5):** 4 JSON-Schemas, 15 Specs,
  6 deterministische Python-Validatoren (`validate_run`, `provenance_validate`, `event_hysteresis`,
  `severity_mapping`, `root_finding`, `contradiction_rules`) + Integritäts-/Release-Tools
  (`freeze_manifest`, `release_gate`, `ark_semver`, `ark_json`, `release_sbom`, `release_bundle`,
  `version_bump`), Testvektoren, `FREEZE_MANIFEST_v1.1.0.json` (SHA-256 je Datei),
  `RELEASE_BUNDLE_v1.1.0.sha256` (gepinnter Digest des Release-Bundles), `CHANGELOG.md`.
- **CI-Gates aktiv (verifiziert 2026-09-28; Zählung lokal 2026-11-18):** `ruff check .` clean · `compileall`
  aller TOOLS/tests · Freeze-Manifest-Gate (NG-002, fail-closed) · `pytest` **488 passed** (lokal 2026-11-21, Windows, py3.12) ·
  Release-SBOM-Pfad (`release_sbom.py`, jeder PR) · Release-Bundle gegen Digest-Pin (`release_bundle.py`, jeder PR, alle 4 Plattform-Jobs) ·
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
- [x] Opt-in `--strict-exit`: Exitcode trägt das Verdikt (0 ACCEPT/ACCEPT_WITH_NOTES, 1 REJECT, 2 Werkzeugfehler = argparse-Usage-Code, 3 REVIEW); Default unverändert. Vertrag in `SPECS/REPORTING_POLICY_v1.md`, Golden-Vektoren `TESTVECTORS/exit/`. _(#37)_
- [x] Interner Absturz (z. B. fehlendes Schema) = Werkzeugfehler statt Traceback-Exit 1 (unter `--strict-exit` sonst als REJECT gelesen); ein alter Report am Ausgabepfad wird dabei entfernt, damit kein veraltetes ACCEPT liegen bleibt. End-to-End-Test auf echtem Prozess-Exitcode. _(#37)_

## Phase 4 — Versionierung (`SPECS/VERSIONING_POLICY_v1.md`, Status PROPOSED)
- [x] `VERSION` als einzige Quelle; Lockstep-Kopien (14+1 Spec-Header, Manifest-Name + `artifact`, `CITATION.cff`, `AGENTS.md`, README-Status, Beispiel-Provenance) per Gate in jedem PR geprüft (`tests/test_version_consistency.py`).
- [x] Release-Gate: Tag muss `v<VERSION>` sein, Manifest-Pfad aus `VERSION` statt hart kodiert; Gate-Skript mit 7 Szenarien unter `bash` und `bash -eo pipefail` getestet.
- [x] Bump-Ablauf end-to-end in einer Repo-Kopie getestet (1.0.5 -> 1.1.0, Freeze-Gate danach in sync).
- [x] `VERSION` im Freeze-Manifest Pflicht (Coverage-Policy).

## Phase 4b — Release-Pfad (GPT-6 R8, 2026-10-21)
- [x] **Release-Blocker behoben:** `release.yml` rief `cyclonedx-py environment --outfile …` — keine gültige Option (Exit 2); der erste Tag wäre nach den Gates und vor der Attestation gescheitert. Unentdeckt, weil der Schritt nur auf Tags lief. Jetzt `TOOLS/release_sbom.py`, in jedem PR von `ci.yml` ausgeführt.
- [x] ARK-R8-002: Runtime-SBOM (`sbom.runtime.cdx.json`) aus sauberer venv nur mit `requirements-runtime.txt`, exakt gegen die Pins geprüft (fail-closed); Build-SBOM separat benannt. Test: jeder Drittanbieter-Import in `TOOLS/` ist gepinnt, CI testet unter genau den attestierten Versionen.
- [x] ARK-R8-003: Tag-Job führt `ruff` + `compileall` wie `ci.yml` (#41 übernommen); struktureller Test verlangt jedes `ci.yml`-Gate auch im Tag-Job.
- [x] Hash-Locks (OpenSSF Scorecard *Pinned-Dependencies*): `requirements-*.in` → `uv pip compile --generate-hashes`; jede Installation mit `--require-hashes --only-binary=:all:`, kein ungepinntes `pip --upgrade` mehr.
- [x] Determinismus: `validate_run` FormatChecker closed-world (`formats=()` + `date-time`) — vorher hing die Menge geprüfter Schema-Formate an installierten Zusatzpaketen (8 bei Konsumenten, 20 in CI).
- [x] Python-Floor-Drift (Doku ≥3.10/≥3.11 vs. CI 3.12) behoben und per Test an die Workflows gebunden.
- [x] ARK-R8-009: CI-Job `portability` (Windows + macOS mit Python 3.12, Ubuntu mit 3.13): hash-gelockte Installation, Freeze-Gate (byte-identischer Checkout je OS), volle Testsuite. Pflicht-Check `gate` unverändert.
- [x] ARK-R8-001 (Quellstand, 2026-11-18): Software-Subjekt im Release. `TOOLS/release_bundle.py` baut `ARK-Core_v<VERSION>_freeze.tar` — exakt die Manifest-Dateien + Manifest, eine kanonische unkomprimierte ustar-Kodierung (keine Uhr, keine Umgebungsvariable, kein zlib), bytegleich auf Linux/Windows/macOS. Digest im Repo gepinnt (`artifacts/RELEASE_BUNDLE_v<VERSION>.sha256`); `ci.yml` und `release.yml` verweigern einen abweichenden Build; `release.yml` attestiert das Bundle als Subject. Vertrag: `SPECS/ARCHIVE_CONFORMANCE_v1.md`.
- [x] ARK-R8-004: Closed-World-Prüfung des ausgelieferten Bundles, getrennt von der bewusst selektiven Freeze-Policy: `release_bundle.py --verify` (eigener strikter Parser, kein `tarfile` auf fremden Bytes; Re-Encoding muss die Eingabe bytegenau ergeben). Negativmatrix in `tests/test_release_bundle.py` (Links, fremde/fehlende Dateien, Metadaten, Pfade, Casing, Anhänge, jede geprüfte Ein-Byte-Änderung); Konsumenten-Probe: prüfen → entpacken → entpackte Tools laufen → Rebuild bytegleich.
- [x] Falsifikation R8-004 am Kopf `ff29b7a` (2026-11-20): ein Bundle-Manifest mit doppeltem JSON-Key (zweites `files`/`artifact`) wurde akzeptiert — Python liest den letzten Wert, andere Parser den ersten (Parser-Differenzial im Closed-World-Verifier). Jetzt I-JSON (RFC 7493) im Bundle-Verifier, im Build und im Freeze-Gate: Duplikat-Keys und `NaN`/`Infinity` -> `NEG.ARCHIVE.MANIFEST_MISMATCH`; Freeze-Gate verweigert auch ein Nicht-Objekt (vorher `AttributeError`). Member-Pfade: `COM0`/`LPT0` reserviert (OneDrive/SharePoint). 11 neue Tests, alle am alten Kopf rot. Verschärfung = MINOR (deckt sich mit dem fälligen 1.1.0).
- [x] Selbstkritik #45 (2026-11-20): Duplikat-Keys galten nur für das Manifest; `validate_run` (Kernel/Policy), `release_gate`, `release_sbom` lasen weiter lax, und RFC 7493 verbietet zusätzlich Surrogate/Nicht-Zeichen (auch escaped). Jetzt **eine** JSON-Grammatik `TOOLS/ark_json.py` (I-JSON, stdlib, Muster `ark_semver`) für alle Entscheidungspfade; Struktur-Test verbietet `json.load(s)` sonst in `TOOLS/`. Abbildung auf bestehende IDs (`NEG.KERNEL.UNREADABLE`, `NEG.POLICY.UNREADABLE`, `NEG.ARCHIVE.MANIFEST_MISMATCH`), keine neue NEG-ID. 32 Tests, 9/9 Mutanten erkannt. Vertrag: `SPECS/STRICT_JSON_SCHEMA_HARDENING_v1.md` „Input grammar“.
- [ ] ARK-R8-001 Rest (**nicht** durch Quellcode erfüllbar): erster echter Tag-Lauf mit Attestation und unabhängigem `gh attestation verify` inkl. Negativprobe (falsches Repo/Ref, verändertes Byte); Attestation-Speicher für das private Repo; geschützte Tags/Ruleset. Owner-/Vero-Schritte, Ablauf in `docs/RELEASE_HARDENING.md` §3a.
- [ ] Wheel/sdist auf einem Index: weiterhin Owner-Entscheid (braucht importierbaren Paketnamen/Layout = Public-Surface-Entscheid; wäre zusätzliches Subject, kein Ersatz).
- [ ] ARK-R8-005 echter Consumer-Receipt DDE→ARK→USK — Owner-Entscheid / Cross-Repo.

## Phase 5 — Release 1.1.0 vorbereitet (2026-11-20)
- [x] Öffentliche Oberfläche seit Origin `b746b6d` **gemessen** statt erinnert: 11 NEG-IDs neu, keine entfernt/umbenannt; CLI-Flags nur ergänzt (`--policy`, `--strict-exit`); Schemas unverändert; Default-Exitvertrag unverändert (Exit 2 nur unter Opt-in) -> MINOR. Lockerungen gezielt gesucht: Closed-World-FormatChecker ist keine (Schemas nutzen nur `date-time`), Provenance ist reine Verschärfung (Origin ignorierte unbekannte Kanten/fehlende IDs); einzige Lockerung #34.
- [x] `CHANGELOG.md` (Keep a Changelog 1.1.0) mit §3-Klassifikation, `verdict-loosening` benannt; Basis-Eintrag 1.0.5 (Origin, nie getaggt). Lockstep-Pflicht + Freeze-Coverage.
- [x] `TOOLS/version_bump.py`: §5 als ein Befehl (alles-oder-nichts-Vorbedingungen: SemVer-Präzedenz nach semver.org §11, keine Drift vorher, Changelog-Abschnitt vorhanden, kein Manifest/Pin für NEW), Freeze/Pin als frische Prozesse (`freeze_manifest` liest seinen Pfad beim Import). Lockstep-Regeln nur noch dort, Test importiert sie.
- [x] Prozesslücken geschlossen: E2E-Bump-Test ließ Bundle-Pin aus (Bundle-Bau wäre nach Bump gescheitert); `tests/test_freeze_manifest.py` hatte `FREEZE_MANIFEST_v1.0.5.json` fest codiert (hätte nach Bump das alte Manifest geprüft, ein Test wäre aus falschem Grund grün geblieben); README/Coverage-Doku versionsneutral. E2E-Test läuft jetzt Bump → Freeze-Gate → Bundle-Bau gegen neuen Pin → Closed-World-Verify → Release-Gate `v<NEW>` → versionsgebundene Tests.
- [x] Bump 1.0.5 -> 1.1.0 mit dem Werkzeug selbst durchgeführt (Dogfooding).

## Offen / zu entscheiden
- **Release 1.1.0 freigeben** (Owner): Kandidat steht (`VERSION` 1.1.0, `CHANGELOG.md` mit gemessener §3-Klassifikation MINOR und der einzigen Verdikt-Lockerung #34). Offen: Merge des Bump-PRs, Tag `v1.1.0` pushen, dann erster echter Release-Lauf mit Attestation und `gh attestation verify` inkl. Negativprobe (`docs/RELEASE_HARDENING.md` §3a).
- VERSIONING_POLICY von PROPOSED auf ACCEPTED (Owner-Entscheid), inkl. Bump-Regel „Lockerung nie PATCH“.
- Phase 2 Schema-Versionen (§4): `schema_version` + `tool{name,version}` im Gate-Report (SARIF-Modell) — bricht Konsumenten mit dem alten Schema (`additionalProperties: false`), braucht Migrationsplan (USK-Adapter).
- `--strict-exit` als Default (#37, Schritt 2): erst wenn alle Aufrufer (CI, USK-Adapter, Skripte) migriert sind; offen, ob REVIEW CI rot färben soll.
- REVIEW und ACCEPT_WITH_NOTES sind aus eigenen `validate_run`-Befunden derzeit unerreichbar (alle gerouteten NEG-IDs non-downgradable): gewollt oder fehlt ein downgradebarer Check?
- Verhältnis zu den übrigen Governance-Stack-Säulen (Cross-Referenz-Specs).
