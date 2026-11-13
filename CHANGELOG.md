<picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/logo-dark.svg"><img alt="OpenCM" src="docs/images/logo.svg" height="40"></picture>

# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/de/1.1.0/), Versionierung: SemVer.

## [Unveröffentlicht] – Behebungen aus dem Review vom 2026-11-13

Regressionstests: `server/test/review-fixes.test.ts`.

### Hinzugefügt
- Eigenes OpenCM-Logo (`docs/images/`): in README, Doku, Web-UI (Favicon, Seitenleiste, Anmeldeseite) und API-Doku (`/api/docs`, Logo, Favicon und Titel „OpenCM API“).

### Sicherheit
- **REV-001:** Passwort setzen, Deaktivieren und Löschen eines Benutzers verlangen jetzt, dass der Ausführende alle Rechte des Zielbenutzers selbst hält. Bisher konnte jeder mit `users:update` das Administrator-Konto übernehmen. Dasselbe gilt für das Aufnehmen eines Benutzers in eine Gruppe mit Rollen (`groupIds` in `POST`/`PATCH /users`).
- **REV-002:** Der MFA-Reset für andere Benutzer unterliegt derselben Prüfung.
- **REV-003:** `POST /runs/{id}/rerun` prüft das Vier-Augen-Prinzip. Massen-Wiederholungen antworten mit `202` und erzeugen eine Freigabeanfrage (neue Aktion `run.rerun`).
- **REV-004 / REV-005:** Jede `machineId` gibt es nur einmal. Ein Enrollment mit der `machineId` eines registrierten Geräts wird mit `409 device_already_enrolled` abgelehnt, auch wenn das Gerät widerrufen ist. Der Token wird dabei nicht verbraucht, der Versuch steht im Audit-Log (`device.enroll_rejected`).
- **REV-006:** Der Windows-Agent übernimmt beim Enrollment den Besitz des Konfigurationsverzeichnisses, entfernt fremde Zugriffsrechte und ignoriert eine dort vorgefundene fremde `agent.json`. Der Agent startet auf allen Plattformen nicht mehr mit Konfiguration oder Schlüsseln, die einem anderen Benutzer gehören. **Dieser Teil ist nicht gebaut und nicht getestet** (kein Go auf der Entwicklungsmaschine).

- **REV-010:** Der Signaturschlüssel für Aufträge (`signing.key`) wird nur noch erzeugt, wenn die Datei fehlt. Ist sie unlesbar oder beschädigt, bricht der Serverstart mit einer klaren Meldung ab, statt still einen neuen Schlüssel zu schreiben, den kein Agent kennt.
- **REV-007:** Testläufe von **Entwürfen** verlangen zusätzlich `scripts:approve`. Freigegebene Versionen lassen sich weiter mit `scripts:execute` testen.
- **REV-008:** Die Vier-Augen-Schwelle lässt sich nicht mehr durch Aufteilen unterlaufen: Die Geräte der eigenen Ausführungen der letzten 60 Minuten zählen mit (`FOUR_EYES_WINDOW_MINUTES`). Testläufe werden ab der Schwelle mit `409 four_eyes_limit` abgelehnt.

### Geändert (inkompatibel)
- `SCRIPT_SELF_APPROVAL` ist jetzt standardmäßig `false`: Der Autor einer Skriptversion kann sie nicht selbst freigeben. Installationen mit nur einem Administrator müssen `SCRIPT_SELF_APPROVAL=true` setzen.
- Erneutes Enrollment desselben Rechners behält die Geräte-ID nicht mehr. Das Gerät muss vorher von einem Administrator gelöscht werden und erscheint danach als neues Gerät. Das Audit-Ereignis `device.reenroll` entfällt.
- Web und CLI (`opencm jobs rerun`) zeigen bei einer Wiederholung mit Freigabepflicht die Freigabeanfrage an; die CLI endet dann mit Exitcode 8.

## [0.8.0] – 2026-11-13 – Meilenstein M7 „OSV, Sicherheitsstatus, Assets“

### Hinzugefügt
- **OSV für Linux-Distributionspakete** (Debian, Ubuntu, Rocky Linux, AlmaLinux):
  - Der Agent meldet Quellpaket und volle Version (dpkg `source:Package`/`source:Version`, rpm SRPM + Epoch) sowie die Distributions-ID.
  - Der Feed `osv` fragt nur neue oder veraltete Paketversionen gebündelt bei osv.dev ab, mit Cache und „Jetzt synchronisieren“.
  - Befunde aus den Sicherheitsmeldungen der Distribution haben Konfidenz „sicher“ und ersetzen für geprüfte Pakete den CPE-Abgleich. Damit entfallen die Fehlalarme durch zurückportierte Fixes.
- **Sicherheitsstatus** je Gerät:
  - Erfasst werden BitLocker/FileVault/LUKS je Laufwerk (inkl. „angehalten“), Microsoft Defender und Fremd-Virenschutz, XProtect, ClamAV, Defender für Linux, Firewall-Profile, Secure Boot und TPM.
  - Bewertung „konform“ mit Problemcodes. Änderungen erscheinen im Geräteverlauf, eine Verschlechterung löst das neue Webhook-Ereignis `device.security_changed` aus.
  - Seite „Sicherheitsstatus“ mit Filtern und CSV-Export, Geräte-Reiter „Sicherheit“, Dashboard-Kachel und zwei Trends.
  - Dynamische Gruppen filtern nach `encryption`, `antivirus`, `firewall` und `securityCompliant`; neue Berichtsquelle „Sicherheitsstatus“.
  - CLI `security status|device`.
- **Assets ohne Agent** (Monitore, Drucker, Telefone, Netzwerkgeräte, Lagergeräte):
  - Erfassung, Bearbeitung und Löschen; eindeutige Inventarnummer; Verknüpfung mit einem verwalteten Gerät (Geräte-Reiter „Zubehör“).
  - CSV-Import im Excel-Format mit Probelauf und CSV-Export; Abgleich über Inventar-, sonst Seriennummer; deutsche Spaltennamen und Datumsformate.
  - Garantie-Übersicht, Berichtsquelle „Assets“, Dashboard-Kachel.
  - Neues Rechte-Modul `assets`; die Systemrolle Helpdesk erhält `assets:read`.
  - CLI `assets list|show|create|update|delete|import`.
- Agent: eigenes, rein lesendes PowerShell-Skript für den Sicherheitsstatus unter Windows (getrennt vom Inventarskript wegen der Längengrenze der Kommandozeile).

### Geändert
- Migration `0008_osv_security_assets`: neue Tabellen `osv_packages`, `osv_vulns`, `device_security`, `assets`; `device_software.source_name` / `source_version`.
- Neue Einstellungen: `OSV_ENABLED`, `OSV_API_URL`, `OSV_SYNC_INTERVAL_HOURS`, `OSV_MAX_PACKAGES_PER_RUN`, `OSV_MAX_DETAILS_PER_RUN`, `SECURITY_AV_MAX_AGE_DAYS`.
- Die Anbindung von Fernwartungs-Tools wurde auf Wunsch gestrichen.

### Behoben
- CLI: `parseFilter` war im Paket doppelt deklariert (Geräteliste und Berichte). Der Go-Build in der CI wäre daran gescheitert. Die Berichtsvariante heißt jetzt `parseReportFilter`.

### Sicherheit / Datenschutz
- An osv.dev gehen ausschließlich Paketnamen, Versionen und das Ökosystem, keine Hostnamen oder Adressen; der Test prüft das. Abschaltbar mit `OSV_ENABLED=false`.
- Der CSV-Export von Assets und Sicherheitsstatus neutralisiert Formel-Injektion. Beim Re-Import wird die Schutzmarkierung wieder entfernt.

## [0.7.0] – 2026-11-12 – Meilenstein M6 „Berichte, Dashboards, Webhooks“

### Hinzugefügt
- **Dashboard** mit Kennzahlen je Bereich (rechte- und geltungsbereichsabhängig), Geräte nach OS und Tagestrends über 30/90/365 Tage. Der Worker schreibt stündlich die Tageswerte (`metrics_daily`).
- **Berichte:**
  - Editor mit 6 Quellen (Geräte, Software, Schwachstellen, ausstehende Updates, Task-Ergebnisse, Softwarelizenzen)
  - Spaltenauswahl, Filter (11 Operatoren), Sortierung, Live-Vorschau
  - private und geteilte Berichte, Export als CSV/JSON (bis 100.000 Zeilen)
  - CLI `reports list|sources|run|query`
- **Webhooks:**
  - 10 Ereignisse (u. a. Hash-Verstoß, Verteilung angehalten, Freigabe angefordert, neue kritische Schwachstellen)
  - Outbox mit Wiederholungen (1 min bis 6 h), HMAC-SHA256-Signatur mit Zeitstempel, Zustellprotokoll, Test, erneut senden, Geheimnis rotieren
  - CLI `webhooks list|create|test|deliveries|redeliver`
- **Softwarelizenzen** (Verwaltung der Lizenzen für Fremdsoftware):
  - Abgleich mit dem Inventar, Überschreitung und Ablauf, Ereignis `license.overused`
  - CLI `licenses list|create`
- CLI `dashboard`.
- **Open Source:** `LICENSE` (MIT); `"license": "MIT"` in allen Paketen.

### Geändert
- Systemrollen (z. B. Auditor) werden beim Start an den aktuellen Rechtekatalog angepasst; neue Module: `reports`, `webhooks`, `licenses`.
- Neue kritische Befunde werden zusätzlich als Webhook-Ereignis gemeldet; `VULN_WEBHOOK_URL` bleibt als Altweg.

### Sicherheit
- Berichte nehmen kein SQL an: Spalten und Operatoren kommen aus festen Listen, Werte werden gebunden; `%`/`_` werden in „enthält“ maskiert.
- Webhook-Ziele: nur https (außer mit `WEBHOOK_ALLOW_HTTP`), keine Zugangsdaten in der URL. Link-Local- und Metadaten-Adressen werden beim Speichern und bei jeder Zustellung (DNS) abgewiesen. Weiterleitungen werden nicht verfolgt, Geheimnisse liegen verschlüsselt.

## [0.6.0] – 2026-11-12 – Meilenstein M5 „Softwareverteilung & Patches“

### Hinzugefügt
- **Paket-Repository:**
  - 11 Pakettypen: MSI, EXE, winget, Chocolatey, DEB, RPM, apt, dnf, PKG, Homebrew, eigene Befehle
  - Upload gestreamt, SHA-256-adressiert und dedupliziert, Größenlimit
  - Versionen mit Freigabe (optional Vier-Augen), nach der Freigabe unveränderlich (DB-Trigger)
  - Vorschau des erzeugten Skripts
- **Erkennungsregeln** (Software mit Version, Datei, Registry, Befehl):
  - auf dem Gerät vor und nach der Installation geprüft
  - auf dem Server gegen das Inventar → Installationsstand je Gerät
  - konfigurierbare Erfolgs- und Neustart-Exitcodes
- **Verteilung in Ringen** (z. B. Test → Pilot → Alle):
  - automatische Weiterschaltung nach Wartezeit und Erfolgsquote, sonst Pause
  - manuelles Weiterschalten, Anhalten, Fortsetzen, Abbrechen
  - keine Doppelzustellung über Ringe hinweg
  - Vier-Augen-Prinzip mit `software:approve` bzw. `patches:approve`
- **Bandbreitenbegrenzung** für Installationsdateien (global und je Gerät), Download über mTLS mit Range-Fortsetzung.
- **Patch-Management:**
  - automatischer und manueller Scan über Windows Update Agent/WSUS, apt, dnf/yum und softwareupdate
  - Übersicht mit Kacheln, Geräte- und Update-Ansicht, Geräte-Tab „Updates“, CSV/JSON-Export
  - Installation nach Klassifikation (kritisch/Sicherheit/alle) oder ausgewählten Updates, mit Neustart-Richtlinie und anschließendem Rescan, in Ringen
- **Agent:** Payload v2 mit Dateien; Download mit SHA-256-Prüfung, Übergabe als `OPENCM_FILE_<n>`.
- **CLI:**
  - `packages list|get|create|add-version|upload|approve|retire|script`
  - `deploy <paket> --ring …`
  - `deployments list|status|promote|pause|resume|cancel`
  - `patches summary|devices|device|scan|install|export`
- **Web:** Softwareverteilung → Pakete, Verteilungen; Sicherheit → Patches.

### Sicherheit
- **Manipulationsschutz:**
  - Alle Skripte, Dateien und erzeugten Schritte erhalten beim Speichern einen SHA-256-Hash plus HMAC-Siegel (Schlüssel `PKI_DIR/integrity.key`, nicht in der DB).
  - Geprüft wird 1:1 beim Anlegen eines Runs, bei der Auslieferung, vor jedem Verteilungsring (Installationsdateien neu gehasht) und auf dem Gerät (Signatur, Schritt-, Datei- und Skriptdatei-Hash).
  - Bei Abweichung wird abgebrochen: Fehler `integrity: …`, Kennzeichen „Hash-Prüfung fehlgeschlagen“, keine Wiederholung, Audit `security.integrity_violation`.
- Freigaben für Verteilungen verlangen das Recht des jeweiligen Moduls (`software:approve` / `patches:approve`).

### Geändert
- Der Worker bindet das Volume `pki` schreibgeschützt ein (Siegelschlüssel).
- `/approvals/{id}/approve|reject` prüft das benötigte Freigaberecht je Anfrage.

## [0.5.0] – 2026-11-12 – Meilenstein M4 „Berechtigungen komplett“

### Hinzugefügt
- **Geltungsbereiche:** Rollen lassen sich Benutzern und Gruppen global oder nur für bestimmte Gerätegruppen zuweisen. Geräte, Inventar, Schwachstellen, Ad-hoc-Skriptläufe, Ausführungen und Ausgaben werden entsprechend gefiltert. Web-Editor unter Benutzer bzw. Gruppen.
- **Vier-Augen-Prinzip:**
  - Freigabe durch eine zweite Person für Massenausführungen (alle Geräte oder ab einstellbarer Geräteanzahl), Behebungs-Jobs mit „sofort ausführen“ und die Aktivierung geplanter Jobs mit breitem Ziel
  - Selbstfreigabe gesperrt, Ablauf nach 24 h, Ablehnung mit Pflicht-Begründung
  - Web „Freigaben“, `opencm approvals list|approve|reject`, API `202 { approvalRequired, approvalId }`
- **Zwei-Faktor-Anmeldung (TOTP):**
  - Einrichtung per QR-Code, 10 Wiederherstellungscodes, Replay-Schutz
  - optional für alle verpflichtend; Admin-Reset
  - `opencm login --otp`
- **API-Tokens:**
  - persönliche `oct_`-Tokens mit optional eingeschränkten Rechten (nie mehr als der Besitzer), Laufzeit-Limit und Widerruf
  - Web unter Profil, `opencm tokens list|create|revoke`
- **LDAP / Active Directory:**
  - Anmeldung mit Anlage beim ersten Login und verschachtelten AD-Gruppen
  - Mapping AD-Gruppe → OpenCM-Gruppe; Login nur für Mitglieder gemappter Gruppen
  - LDAPS/StartTLS mit eigener CA, Verbindungstest im Web
- **Audit-Export:** CSV (Excel-tauglich, Schutz vor Formel-Injection) und JSON, gefiltert nach Aktion und Zeitraum; Web und `opencm audit export`.
- **Einstellungen „Sicherheit“** zur Laufzeit (Vier-Augen-Schwelle, MFA-Pflicht); `.env` liefert nur die Startwerte.
- CLI-Exitcode 8 = wartet auf Freigabe.

### Geändert
- `requirePermission` wertet nur noch globale Rollen aus; eingeschränkte Rollen wirken ausschließlich auf gerätebezogene Routen.
- Verzeichnisbenutzer können ihr Passwort nicht in OpenCM ändern (409).

### Sicherheit
- TOTP-Geheimnisse AES-256-GCM-verschlüsselt (`PKI_DIR/secrets.key` – mit sichern!), Wiederherstellungscodes nur als Hash.
- Tokens können keine weiteren Tokens erzeugen und keine MFA-Einstellungen ändern.
- LDAP: RFC-4515-Escaping und Ablehnung leerer Passwörter (verhindert „unauthenticated bind“).

## [0.4.0] – 2026-11-12 – Meilenstein M3 „CVE-Erkennung“

### Hinzugefügt
- **Feeds:**
  - NVD CVE API 2.0 als Spiegel: wiederaufnehmbar, inkrementell, Rate-Limit-Backoff, „Rejected“-CVEs werden entfernt
  - CISA KEV mit Frist und Ransomware-Bezug
  - FIRST EPSS nur für betroffene CVEs
  - eigene Worker-Queue, Lease-Lock gegen Parallelläufe, „Jetzt synchronisieren“
- **Zuordnung Software → CPE:**
  - ca. 60 mitgelieferte Regeln (Windows-, macOS- und Linux-Software, Rauschfilter für Redistributables und Updates)
  - eigene Regeln mit Glob-Mustern (ReDoS-sicher), Heuristik gegen NVD-Produkte
  - Vorschläge für nicht zugeordnete Software, Testfunktion für Muster
- **Abgleich:**
  - Versionsvergleich nach rpmvercmp, Normalisierung von dpkg-, rpm- und „v“-Versionen
  - exakte Versionen und Versionsbereiche; Konfidenz sicher/wahrscheinlich/unbestätigt (Distributions-Backports)
- **Befunde:** Lebenszyklus offen → behoben → wieder offen, Neubewertung nach jedem Sync und je neuem Inventar
- **Risikoakzeptanz** je CVE mit Pflicht-Begründung (auditiert)
- **Behebungs-Jobs** direkt aus einer CVE für alle betroffenen Geräte (optional sofort ausführen); **Skript-Vorlagen** winget-Update, Deinstallation per MSI/Registry, Chocolatey, apt, dnf, macOS softwareupdate (Import als Entwurf)
- **Webhook** für neue kritische oder KEV-Befunde (HMAC-SHA256-signiert)
- **Flotten-Softwareinventar** (`GET /software`) mit Zuordnung
- **Web:**
  - Schwachstellen-Übersicht (Kacheln, Filter, Feed-Status), CVE-Detail (CVSS, EPSS, KEV, Referenzen, betroffene und behobene Geräte, Akzeptanz, Behebung)
  - Seite „Software & Zuordnung“ mit Regelverwaltung, Geräte-Tab „Schwachstellen“, Dashboard-Kacheln, Skript-Import aus Vorlagen
- **CLI:** `cve list|get|summary|accept|remediate|sync`, `software`

### Geprüft mit echten Daten
- Netzwerktest: NVD, CISA KEV, FIRST EPSS und OSV sind vom Server erreichbar
- Live-Abgleich des realen Inventars des Entwicklungsservers: keine Fehlalarme bei aktueller Software (Adobe Reader gegen 1.832 CVEs, 7-Zip, KeePass); echter Befund bei einer veralteten Fernwartungssoftware

## [0.3.0] – 2026-11-12 – Meilenstein M2 „Skripte & Jobs“

### Hinzugefügt
- **Skript-Bibliothek:** PowerShell, CMD, bash, zsh, Python. Unveränderliche Versionen (per DB-Trigger erzwungen) mit SHA-256, Parameterdefinitionen (Text/Zahl/Ja-Nein, Pflicht, Standard), Freigabe-Workflow Entwurf → freigegeben → zurückgezogen, optional ohne Selbstfreigabe (`SCRIPT_SELF_APPROVAL`)
- **Testlauf** einer beliebigen Version (auch Entwurf) auf einem Gerät mit Live-Ausgabe; **Ad-hoc-Ausführung** freigegebener Skripte auf beliebigen Zielen (`POST /scripts/{id}/run`)
- **Jobs:**
  - mehrere Schritte (Job-Sammlung) mit Reihenfolge, „Fehler ignorieren“ und Stopp bei Fehler
  - Ziele: Geräte, statische oder dynamische Gruppen, alle Geräte
  - Auslöser: manuell, einmalig, Cron (mit Zeitzone und DST), Agent-Start, Benutzer-Login
  - Timeout, Wiederholungen mit Pause, Wartungsfenster (auch über Mitternacht)
- **Runs & Tasks:** Snapshot je Run, Status je Gerät, Live-Ausgabe mit Cursor, Abbrechen (wartend sofort, laufend über den Agent), Wiederholen für fehlgeschlagene Geräte, Ausgabelimit
- **Signierte Ausführung:** Ed25519-Envelope je Auftrag. Der Agent prüft Signatur, Geräte, Ablauf und Hashes; Parameter kommen ausschließlich als Umgebungsvariablen an.
- **Dynamische Gruppen:** Filter auf Gerätefelder, Online-Status, installierte Software und eigene Felder (UND/ODER), Vorschau. Statische Gruppen mit Mitgliederpflege.
- **Eigene Inventarfelder:** Text/Zahl/Ja-Nein/Datum, manuell oder automatisch aus der letzten Ausgabezeile eines Job-Schritts (Inventar-Skripte)
- **Agent-Selbstupdate:** signiertes Angebot im Heartbeat, Download über mTLS, Prüfung von Hash und Signatur, Austausch des Binaries (Windows: Umbenennen der laufenden Datei), Neustart über den Dienstmanager, nie während eines Tasks
- **Agent (Go):** Long-Poll-Task-Schleife, Executor mit Streaming (UTF-8-sicher), Timeout und Abbruch inkl. Prozessbaum, Replay-Schutz, `quser`-basierte Login-Erkennung unter Windows
- **Worker:** Scheduler-Tick alle 15 s (mehrinstanzfähig); im Dev-Modus mit eingebetteter DB läuft er im Serverprozess
- **Web:** Skripte (Editor mit Syntax-Highlighting, Versionen, Freigabe, Testlauf), Jobs (Editor, Detail, Runs), Run-Ansicht mit Live-Ausgabe, Aktivität, Gerätegruppen mit Filter-Builder, Inventarfelder, Tab „Eigene Felder“ am Gerät
- **CLI:** `scripts list|get|run --target group:X --param k=v --watch`, `jobs list|run|status --watch|cancel|rerun|runs`, `tasks output --follow`, `groups list|members`, Exitcode 7 bei fehlgeschlagenen Geräten

### Behoben
- **PATCH-Endpunkte setzten weggelassene Felder zurück** (zod 4 wendet Defaults auch in `.partial()` an). Betroffen war u. a. `PATCH /roles/{id}`: Eine reine Umbenennung leerte die Rechte der Rolle. Behoben und mit Regressionstest abgesichert.

### Geändert
- Editor: CodeMirror 6 statt Monaco (Begründung: kritische CVE in Monacos eingebettetem DOMPurify, siehe `docs/architecture.md`)

## [0.2.0] – 2026-11-12 – Meilenstein M1 „Agent & Inventar“

### Hinzugefügt
- **PKI:** eigene Agent-CA (ECDSA P-256), automatisch erneuertes Server-Zertifikat für den Agent-Endpoint, CSR-basierte Client-Zertifikate (CN = Geräte-ID, vom Server vergeben)
- **Enrollment:** Tokens mit Ablauf, max. Nutzungen und optionaler Ziel-Gerätegruppe. Der Token wird nur gehasht gespeichert und einmalig mit Installationsbefehlen für Windows, Linux und macOS angezeigt. Bei erneutem Enrollment derselben Maschine bleibt die Geräte-ID erhalten.
- **mTLS-Agent-Endpoint (:8443):** Heartbeat, Inventar-Upload, Zertifikatserneuerung. Widerruf und Löschen wirken sofort (Abgleich des Fingerprints bei jeder Anfrage). Eigene Spec `server/openapi-agent.yaml`.
- **Inventar:** Snapshot, normalisierte Software-Tabelle, Änderungshistorie per Diff (flüchtige Werte ausgenommen)
- **Geräte-API:** Liste (Filter OS/Status/online/Suche, Sortierung), Detail, Inventar, Software, Historie, Inventar anfordern, Widerrufen, Löschen
- **Agent-Downloads:** öffentliche Liste mit SHA-256 und Download je OS/Arch
- **Agent (Go):** `enroll`, `install`/`uninstall` (Windows-Dienst, systemd, launchd), `run`, `status`, `inventory`. Collectors für Windows (PowerShell/CIM/ADSI, live verifiziert), Linux (procfs/sysfs, dpkg/rpm, systemd) und macOS (system_profiler, launchctl, dscl). Exponentielles Backoff, Jitter, automatische Zertifikatserneuerung. Datenverzeichnis per ACL bzw. 0700 geschützt.
- **Web:** Geräteliste, Gerätedetail mit 7 Tabs, Seite „Geräte hinzufügen“ (Tokens, Installationsbefehle, Downloads)
- **CLI:** `devices list|get|software|history|inventory|request-inventory|revoke|delete` (inkl. `--filter "os=windows"`), `enrollment-tokens list|create|revoke`, `agent downloads|download`
- **CI:** Server-Tests zusätzlich gegen echtes PostgreSQL 16, Release-Artefakte mit `version.txt` und `SHA256SUMS`
- `docs/operations.md` (Betriebshandbuch)

### Behoben
- Leere Umgebungsvariablen (`${VAR:-}` aus Docker Compose) verhinderten den Serverstart. Sie gelten jetzt als nicht gesetzt.
- Body-lose POST-Anfragen mit `Content-Type: application/json` wurden mit 400 abgelehnt. Sie werden jetzt akzeptiert; der Schutz vor Prototype Poisoning bleibt erhalten.
- PGlite-Testtreiber: jsonb-Strings wurden doppelt geparst (`"131.0"` → `131`).

### Performance
- Windows-Inventar: Gruppenmitglieder per ADSI statt CIM-Assoziation, auf einer Domänen-Maschine 3 s statt 50 s.

## [0.1.0] – 2026-11-12 – Meilenstein M0 „Fundament“

### Hinzugefügt
- Monorepo: `server`, `web` (npm-Workspaces), `cli`, `agent` (Go-Module), `deploy`, `docs`
- **Server:** Fastify-API `/api/v1`, Drizzle-Schema + Migrationen (Benutzer, Gruppen, Rollen, Rollen-Zuweisungen mit Scope-Vorbereitung, Sessions, API-Tokens, Audit-Log, Geräte- und Gerätegruppen-Gerüst), automatische Migration beim Start, Bootstrap-Admin
- **Auth:** lokaler Login mit Argon2id, Session-Token (Bearer + httpOnly-Cookie), Logout, `GET /auth/me`, Rate-Limit auf Login, gleiche Fehlermeldung für unbekannte Benutzer und falsches Passwort (inkl. Timing-Angleichung)
- **RBAC:** Rechtekatalog `modul:aktion` mit Wildcards, Systemrollen Administrator/Auditor/Helpdesk, CRUD für Benutzer/Rollen/Gruppen, Rechte über Gruppen, Eskalationsschutz
- **Audit-Log:** append-only per DB-Trigger, Filter und Pagination, Login-Fehlversuche werden protokolliert
- **OpenAPI 3.1** (`server/openapi.yaml`), Swagger-UI unter `/api/docs`, Contract-Test Route ↔ Spec
- **Web:** Login, Navigation nach Rechten, Seiten für Benutzer, Rollen (Rechte-Matrix), Gruppen und Audit-Log, Hell-/Dunkelmodus, typisierter API-Client aus der Spec
- **CLI:** `login` (Profile, `--password-stdin`), `logout`, `whoami`, `profile list|use`, `users list|get|create|activate|deactivate|delete`, `roles list`, `audit list`, `--output table|json|yaml`, Shell-Completion, definierte Exitcodes
- **Agent:** Skelett mit Konfiguration (HTTPS-Pflicht), JSON-Logging, Run-Loop, sauberem Shutdown
- **Deployment:** Docker Compose (postgres, redis, server, worker, web, Caddy mit Let's Encrypt), Healthchecks, `.env.example`, `backup.sh`/`restore.sh`
- **CI:** GitHub Actions (Typecheck, Tests, Web-Build, npm audit, Go vet/test auf 3 OS, Cross-Compile für 6 Ziele, Docker-Builds, Compose-Validierung)
- 32 Server-Tests (Unit + Integration gegen PGlite mit echten Migrationen), Go-Unit-Tests für CLI-Ausgabe und Agent-Konfiguration
