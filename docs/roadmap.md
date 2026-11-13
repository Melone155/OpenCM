<picture><source media="(prefers-color-scheme: dark)" srcset="images/logo-dark.svg"><img alt="OpenCM" src="images/logo.svg" height="40"></picture>

# Roadmap und Funktionsumfang

**Status:** ✅ fertig · 🟡 teilweise/Gerüst · ⬜ offen
**Priorität:** P1 = MVP · P2 = danach · P3 = später

| # | Bereich | Funktion | OpenCM-Umsetzung | Meilenstein | Prio | Status |
|---|---|---|---|---|---|---|
| 1 | Administration | Benutzer verwalten (lokal) | `users`, `/users`, Web „Benutzer“, `opencm users` | M0 | P1 | ✅ |
| 2 | Administration | Rollen mit granularen Rechten je Modul/Aktion | `roles.permissions` (`modul:aktion`), Rechte-Matrix im Web | M0 | P1 | ✅ |
| 3 | Administration | Benutzergruppen mit Rollen | `groups`, `group_roles`, `user_groups`, Web-Editor für Rollen und AD-Gruppe | M0/M4 | P1 | ✅ |
| 4 | Administration | Rechte auf Gerätegruppen/Standorte beschränken | Rollenzuweisung mit `scopeDeviceGroupIds`; gerätebezogene Routen gefiltert (außerhalb = 404), Verwaltungsrechte nur global | M4 | P1 | ✅ |
| 5 | Administration | AD/LDAP-Anmeldung und -Benutzerimport | ldapts, Bind + Suche, verschachtelte AD-Gruppen, Gruppen-Mapping `groups.ldap_group`, Anlage beim ersten Login, Verbindungstest | M4 | P1 | ✅ (nur gegen simuliertes Verzeichnis getestet) |
| 6 | Administration | OIDC/SAML-SSO | – | M4+ | P2 | ⬜ |
| 7 | Administration | MFA (TOTP) | RFC 6238, QR-Einrichtung, Replay-Schutz, 10 Wiederherstellungscodes, optional verpflichtend, Admin-Reset, `opencm login --otp` | M4 | P1 | ✅ |
| 8 | Administration | Protokollierung aller Benutzeraktionen | `audit_log` (append-only per Trigger), `/audit-log`, Export CSV/JSON (`/audit-log/export`, `opencm audit export`) | M0/M4 | P1 | ✅ |
| 9 | Administration | Vier-Augen-Freigabe kritischer Aktionen | `approval_requests`: Massenausführungen (alle Geräte / ab Schwelle) und Aktivierung breiter Zeitpläne; Selbstfreigabe gesperrt, Web „Freigaben“, `opencm approvals` | M4 | P1 | ✅ |
| 10 | Administration | API-Zugänge/Tokens | `oct_`-Tokens (Hash), Rechte = Schnittmenge mit Besitzer, Laufzeit-Limit, Widerruf, Web + `opencm tokens` | M4 | P1 | ✅ |
| 11 | Agent | Agent für Windows/Linux/macOS, nur ausgehende Verbindungen | `opencm-agent` (Go): Dienst unter Windows/systemd/launchd | M1 | P1 | ✅ (Go-Build nur in CI) |
| 12 | Agent | Registrierung neuer Clients | Enrollment-Token (Ablauf, max. Nutzungen, Zielgruppe) → CSR → Client-Zertifikat, mTLS-Endpoint :8443, sofortiger Widerruf | M1 | P1 | ✅ |
| 13 | Agent | Online-/Offline-Status, letzter Kontakt | Heartbeat (60 s), online = Kontakt in 3 Intervallen, Filter in Liste/CLI | M1 | P1 | ✅ |
| 14 | Agent | Agent-Installer zum Download, Selbstupdate | Download + SHA-256, Installationsbefehle je OS; signiertes Selbstupdate über Heartbeat | M1/M2 | P1 | ✅ |
| 15 | Inventarisierung | Hardware (CPU, RAM, Datenträger, Netzwerk, BIOS, Seriennummer, Hersteller/Modell) | Collectors je OS → `device_inventory` | M1 | P1 | ✅ (Windows live verifiziert) |
| 16 | Inventarisierung | Betriebssystem + Patchstand | OS-Version/Build/Kernel, installierte Patches (Win/macOS); ausstehende Updates aller Plattformen per Patch-Scan (M5) | M1/M5 | P1 | ✅ |
| 17 | Inventarisierung | Installierte Software (Version, Hersteller, Installationsdatum) | `device_software` (normalisiert, Basis für M3): Registry/MSI/MSIX, dpkg/rpm, macOS-Apps | M1 | P1 | ✅ |
| 18 | Inventarisierung | Dienste, Autostart, lokale Benutzer/Gruppen, angemeldeter Benutzer | im Snapshot + Gerätedetail-Tabs | M1 | P1 | ✅ |
| 19 | Inventarisierung | Eigene Felder + eigene Inventar-Skripte | `custom_fields` (Text/Zahl/Ja-Nein/Datum), manuell oder per Job-Schritt aus der Skriptausgabe | M2 | P1 | ✅ |
| 20 | Inventarisierung | Änderungshistorie pro Gerät | `device_history` per Diff, ohne flüchtige Werte | M1 | P1 | ✅ |
| 21 | Inventarisierung | Geräte ohne Agent (Assets) | `assets`: Typ, Status, Hersteller/Modell, Serien- und Inventarnummer (eindeutig), Standort, Person, IP/MAC, Kaufdatum, Garantie, Kosten, Verknüpfung mit verwaltetem Gerät; CSV-Import (Excel-Format, Probelauf, Abgleich über Inventar-/Seriennummer) und -Export; Berichtsquelle, Dashboard-Kachel „Garantie läuft ab“; Web „Assets“, Geräte-Reiter „Zubehör“, `opencm assets` | M7 | P3 | ✅ (Netzwerk-Scan zur automatischen Erkennung: offen) |
| 22 | Client-Steuerung | Skript-Bibliothek (PowerShell, Bash, zsh, Python, CMD) | `scripts` + unveränderliche `script_versions` | M2 | P1 | ✅ |
| 23 | Client-Steuerung | Parameter, Versionierung, Freigabe (Entwurf → freigegeben) | Parameter als Env-Variablen, Freigabe/Zurückziehen, optional ohne Selbstfreigabe | M2 | P1 | ✅ (Vier-Augen: M4) |
| 24 | Client-Steuerung | Editor mit Syntax-Highlighting, Testlauf auf einem Gerät | CodeMirror 6 (statt Monaco, s. Architektur), Testlauf auch für Entwürfe | M2 | P1 | ✅ |
| 25 | Client-Steuerung | Live-Ausgabe stdout/stderr/Exitcode | Streaming vom Agent, Cursor-Polling in Web/CLI, Exitcode je Schritt | M2 | P1 | ✅ |
| 26 | Client-Steuerung | Visueller Baustein-Editor | – | M6+ | P3 | ⬜ |
| 27 | Jobs | Job = Aktion + Ziel + Zeitplan + Bedingungen | Jobs mit Schritten, Zielen, Auslösern, Optionen; Interpreter-Kompatibilität je OS | M2 | P1 | ✅ |
| 28 | Jobs | Statische und dynamische Gerätegruppen | Filter auf Gerätefelder, Online, Software, eigene Felder, Sicherheitsstatus (M7) (UND/ODER) + Vorschau | M2/M7 | P1 | ✅ |
| 29 | Jobs | Zeitpläne: sofort, einmalig, Cron, Agent-Start, Benutzer-Login | alle fünf; Cron mit Zeitzone | M2 | P1 | ✅ |
| 30 | Jobs | Job-Sammlungen mit Reihenfolge, Wartungsfenster, Retry, Timeout | Schritte je Job, Wartungsfenster, Wiederholungen, Timeout | M2 | P1 | ✅ (Abhängigkeiten zwischen Jobs: offen) |
| 31 | Jobs | Status pro Gerät, Abbrechen, Neu ausführen | Tasks je Gerät, Abbruch (auch laufend), Wiederholen fehlgeschlagener Geräte | M2 | P1 | ✅ |
| 32 | Schwachstellen | Abgleich der Software mit NVD/CPE, CISA KEV, OSV | NVD-Spiegel (wiederaufnehmbar, inkrementell), KEV, EPSS; OSV für Linux-Distributionspakete (Debian, Ubuntu, Rocky, AlmaLinux) über Quellpakete mit exakter Version – ersetzt für geprüfte Pakete den CPE-Abgleich (keine Backport-Fehlalarme) | M3/M7 | P1 | ✅ (RHEL, SUSE, Alpine: offen) |
| 33 | Schwachstellen | Software → CPE-Mapping inkl. manueller Regeln | ~60 mitgelieferte Regeln + eigene Glob-Regeln + Heuristik gegen NVD-Produkte, Vorschläge für nicht zugeordnete Software | M3 | P1 | ✅ |
| 34 | Schwachstellen | Übersicht betroffener Geräte, CVSS, KEV-Markierung, EPSS | Risiko-sortierte Liste, Kacheln, Gerätedetail, Risikoakzeptanz, Konfidenzstufen | M3 | P1/P2 | ✅ |
| 35 | Schwachstellen | Behebungs-Job direkt aus der Schwachstelle | Job mit freigegebenem Skript für alle betroffenen Geräte (+ sofort ausführen); Vorlagen winget/MSI/choco/apt/dnf/macOS | M3 | P1 | ✅ |
| 36 | Softwareverteilung | Pakete (MSI/EXE/winget/choco, apt/dnf, pkg/brew) mit Erkennungsregeln | 11 Typen inkl. DEB/RPM und eigene Befehle; Erkennung per Software/Datei/Registry/Befehl vor und nach der Installation; Exitcode- und Neustart-Codes; Freigabe, unveränderliche Versionen; Installationsstand aus dem Inventar; Verteilung in Ringen mit automatischer Weiterschaltung, Pause unter Erfolgsquote, Vier-Augen | M5 | P2 | ✅ |
| 37 | Softwareverteilung | Paket-Repository, Bandbreitenbegrenzung | inhaltsadressiert (SHA-256, dedupliziert) im Volume `files`, Upload gestreamt; Download über mTLS mit Range-Fortsetzung, Token-Bucket global + je Gerät | M5 | P2 | ✅ (keine Verteilpunkte/P2P: P3) |
| 38 | Patch-Management | Windows-/Linux-/macOS-Updates, Freigaberinge, Berichte | Scan (Windows Update Agent/WSUS, apt, dnf, softwareupdate) automatisch + manuell; Installation nach Klassifikation oder Auswahl in Ringen, Neustart-Richtlinie, Rescan; Patchstand-Übersicht, Geräte-/Update-Ansicht, CSV | M5 | P2 | ✅ |
| 38a | Sicherheit | Manipulationsschutz für Skripte und Dateien | SHA-256 beim Speichern, 1:1-Prüfung vor Run-Anlage, Auslieferung und auf dem Gerät; HMAC-Siegel (Schlüssel außerhalb der DB); Abbruch mit „Hash-Prüfung fehlgeschlagen“ + Audit | M5 | P1 | ✅ |
| 39 | Sicherheit | BitLocker-/Defender-Status | Inventarabschnitt `security`: BitLocker/FileVault/LUKS je Laufwerk (inkl. „angehalten“), Defender + Fremd-Virenschutz (Security Center), XProtect, ClamAV, Defender für Linux; Firewall-Profile, Secure Boot, TPM. Bewertung „konform“, Problemcodes, Verlauf, Ereignis `device.security_changed`, Gruppenfilter, Berichtsquelle, Dashboard + Trend; Web „Sicherheitsstatus“, Geräte-Reiter, `opencm security` | M7 | P3 | ✅ (Windows-Skript live verifiziert, macOS/Linux nur Parser-Tests) |
| 40 | Lizenzen | Softwarelizenz-Verwaltung (Lizenzen der Anwender für Fremdsoftware) | Muster auf Inventar-Software, genutzt/frei/überschritten, Ablauf, Kosten, Geräteliste, Ereignis `license.overused`, Berichtsquelle | M6 | P3 | ✅ |
| 41 | Helpdesk | Tickets mit Gerätebezug | Anbindung externer Ticketsysteme per Webhook (eigenes Ticketsystem nicht geplant) | M6+ | P3 | 🟡 |
| 42 | Fernwartung | Anbindung von Fernwartungs-Tools | nicht geplant | – | – | – |
| 43 | Berichte | Abfrage-Builder, Dashboards, CSV/PDF-Export | Bericht-Editor mit 8 Quellen (M7: Sicherheitsstatus, Assets), Spalten/Filter/Sortierung, private/geteilte Berichte, CSV/JSON (PDF über Browserdruck); Dashboard mit Kacheln und Tagestrends | M6 | P3 | ✅ (PDF-Export: offen) |
| 44 | Integration | Webhooks (Job fertig, kritische CVE, Gerät offline) | Outbox mit Wiederholungen, HMAC-Signatur, 11 Ereignisse (M7: Sicherheitsstatus verschlechtert), Zustellprotokoll, Schutz vor Metadaten-/Link-Local-Zielen | M6 | P2 | ✅ („Gerät offline“: offen) |
| 45 | Integration | Vollständige REST-API + CLI | OpenAPI 3.1 (Contract-Test für alle Routen), CLI für alle Module | M0–M7 | P1 | ✅ |
| 46 | Projekt | Open Source | MIT-Lizenz, keine Beschränkungen | – | – | ✅ |

> Agent und CLI (Go) werden ausschließlich in der CI gebaut.

## Mögliche Erweiterungen

- Inventarisierung ohne dauerhaft installierten Agent (Einmal-Scanner, Offline-Erfassung)
- Inventar von Netzwerkgeräten über SNMP
- Verschachtelte Gerätegruppen; Aktionen auslösen, wenn ein Gerät einer Gruppe beitritt
- Visueller Baukasten für Automatisierungen (#26)
- Paketierungs-Assistent mit bekannten Silent-Parametern je Installer-Typ
- Wartungsprofile mit Kalender (einzelne und wiederkehrende Zeiträume) je Gerätegruppe, Ausnahmeliste für Jobs, protokolliertes Übersteuern
- Benutzerdialog bzw. Self-Service-Bereich am Gerät (Software selbst auswählen, Hinweise anzeigen)
- Eigene Windows-Update-Ablage, Treiber-Updates, mehrere verteilte Dateiablagen
- Virenschutz und Laufwerksverschlüsselung verwalten, nicht nur anzeigen
- Assets mit Verträgen, Dokumenten und kaufmännischen Daten
- Berichte mit Zeitplan und E-Mail-Versand, PDF-Export
- Rechte auf einzelne Ordner/Objekte (z. B. Skript- oder Berichtsordner)
- Mandantenfähigkeit
- Bearbeitungssperren gegen gleichzeitiges Ändern desselben Objekts
- Weitere Inventar-Reiter: Akku, Monitore, Drucker, Freigaben, Anmeldeverlauf
- Agent aus der Weboberfläche auf Rechner verteilen, Agent fern deinstallieren, Geräte „außer Betrieb“ nehmen
- Regel-Engine für automatische Reaktionen
- Job-Prioritäten; Startbedingungen „beim Herunterfahren“, „nur einmal je Gerät“, Zeitrahmen; lesbare Beschreibung von Zeitplänen
