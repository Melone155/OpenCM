<picture><source media="(prefers-color-scheme: dark)" srcset="images/logo-dark.svg"><img alt="OpenCM" src="images/logo.svg" height="40"></picture>

# Betriebshandbuch

## Installation
Siehe `README.md` → Schnellstart. Kurzfassung: `deploy/.env` aus `.env.example` erzeugen, dann `docker compose pull && docker compose up -d` (fertige Images aus `ghcr.io/melone155`) oder selbst bauen mit `docker compose up -d --build`.

| Port | Dienst | Hinweis |
|---|---|---|
| 443/80 | Caddy → Web-UI + REST-API | Let's Encrypt automatisch für `OPENCM_DOMAIN` |
| 8443 | Agent-Endpoint (mTLS) | **direkt** vom `server`-Container veröffentlicht. TLS muss im Server enden; ein vorgeschalteter TLS-Proxy würde das Client-Zertifikat verlieren. In der Firewall von den Client-Netzen aus freigeben. |

## Agenten

### PKI
- Beim ersten Start erzeugt der Server eine eigene CA (ECDSA P-256, 20 Jahre) in `PKI_DIR` (Volume `pki`): `ca.crt`, `ca.key`.
- Das Zertifikat des Agent-Endpoints (`agent-endpoint.crt/.key`) wird aus dieser CA ausgestellt. SANs: Host aus `PUBLIC_URL`, Host aus `AGENT_PUBLIC_URL`, `localhost` und `AGENT_TLS_HOSTNAMES`. Es wird automatisch erneuert, wenn es weniger als 30 Tage gilt oder sich die Hostnamen ändern (beim Serverstart).
- Client-Zertifikate laufen `AGENT_CERT_DAYS` Tage (Standard 365). Agents erneuern sie ab 30 Tage vor Ablauf selbstständig.
- **`ca.key` ist das wichtigste Geheimnis der Installation.** Es ist im Backup enthalten (`backup.sh`), das Backup muss deshalb verschlüsselt und zugriffsbeschränkt abgelegt werden. Geht die CA verloren, müssen alle Agents neu registriert werden.

### Agent-Binaries bereitstellen
Das Server-Image enthält die Agent-Binaries für windows, linux und darwin (amd64/arm64), gebaut beim Docker-Build (`AGENT_BUNDLED_DIR=/app/agent-dist`). Es ist also nichts zu tun. Die Version der Binaries ist die des Images (`sha-<commit>` bzw. die Release-Version); Images, die ohne `VERSION` gebaut wurden, tragen `dev` und werden Agents nie als Update angeboten.

Eigene Binaries (z. B. das CI-Artefakt `binaries` mit `version.txt`) haben Vorrang, sobald `AGENT_DOWNLOAD_DIR` welche enthält:
```bash
docker compose cp ./dist/. server:/data/files/agent/
```
Sie sind unter `/api/v1/agent-downloads` gelistet und im Web unter „Geräte hinzufügen“ sichtbar.

### Geräte registrieren
1. Web → **Geräte hinzufügen** → Token erstellen (Gültigkeit, max. Anzahl Geräte), oder per CLI: `opencm enrollment-tokens create --name "Rollout" --max-uses 25`.
2. Den angezeigten einzeiligen Befehl auf dem Gerät ausführen: unter Windows in einer PowerShell als Administrator, unter Linux und macOS als root. Er lädt den Agent, registriert ihn und installiert den Dienst.

   Ablauf: Der Befehl lädt `/api/v1/agent-install/<os>` (ein vom Server erzeugtes Skript ohne Geheimnisse), prüft dessen SHA-256 gegen den Wert im Befehl und führt es in einer eigenen Shell aus. Das Skript lädt das Binary, prüft dessen SHA-256 und registriert den Agent mit `--server-pin sha256:…` (Hash über CA-Zertifikat des Agent-Endpoints und Signaturschlüssel). Das HTTPS-Zertifikat der Weboberfläche muss der Client deshalb nicht kennen (`curl -k` / ohne Zertifikatsprüfung). Ein Angreifer im Netz könnte dabei höchstens das Token mitlesen, den Agent aber nicht auf einen fremden Server lenken: Alle weiteren Verbindungen laufen per mTLS gegen die gepinnte CA, Aufträge brauchen die gepinnte Signatur. Ändern sich die Binaries (neues Image), wird der Befehl ungültig (Prüfsummenfehler) – dann ein neues Token erzeugen.
3. Das Gerät erscheint nach wenigen Sekunden in der Geräteliste. Das erste Inventar folgt mit dem ersten Heartbeat.

Manuell:
```text
opencm-agent enroll --server https://cm.example.org --token oce_…   [--ca-file interne-ca.pem]
opencm-agent install
opencm-agent status        # Geräte-ID, Endpoint, Zertifikatsablauf
opencm-agent inventory     # lokales Inventar als JSON ansehen (sendet nichts)
opencm-agent uninstall
```

| OS | Programm | Konfiguration / Daten | Dienst | Log |
|---|---|---|---|---|
| Windows | `C:\Program Files\OpenCM\opencm-agent.exe` | `C:\ProgramData\OpenCM\agent.json`, `…\data\` (ACL: nur SYSTEM/Administratoren) | `OpenCMAgent` (automatisch, verzögert, Neustart bei Fehler) | `C:\ProgramData\OpenCM\logs\agent.log` |
| Linux | `/usr/local/bin/opencm-agent` | `/etc/opencm/agent.json`, `/var/lib/opencm/` (0700) | systemd `opencm-agent` | `journalctl -u opencm-agent` |
| macOS | `/usr/local/bin/opencm-agent` | `/Library/Application Support/OpenCM/` | launchd `org.opencm.agent` | `/Library/Logs/OpenCM/agent.log` |

### Verhalten
- Heartbeat alle `AGENT_HEARTBEAT_SECONDS` (Standard 60 s, ±10 % Jitter). Ein Gerät gilt als **online**, wenn es sich innerhalb von 3 Intervallen gemeldet hat.
- Vollständiges Inventar alle 24 h oder sofort auf Anforderung („Inventar anfordern“ im Web / `opencm devices request-inventory <id>`).
- Bei Verbindungsfehlern verdoppelt sich der Abstand bis maximal 15 min (exponentielles Backoff).
- **Widerruf** (`Widerrufen` im Web / `opencm devices revoke <id>`) wirkt sofort. Ein widerrufenes Gerät bleibt widerrufen; ein Enrollment-Token hebt den Widerruf nicht auf.
- **Jede `machineId` gibt es nur einmal.** Meldet sich ein bereits registrierter Rechner (aktiv oder widerrufen) erneut an, antwortet der Server mit `409 device_already_enrolled`, schreibt den Audit-Eintrag `device.enroll_rejected` und verbraucht den Token nicht. Soll ein Rechner neu registriert werden (Neuinstallation, nach Widerruf), löscht ein Administrator das Gerät zuerst (`Löschen` im Web / `opencm devices delete <id>`). Der Rechner erscheint danach als neues Gerät mit neuer ID; Verlauf und Gruppenzuordnung des alten Geräts sind mit dem Löschen entfernt.
- **Windows-Agent:** `enroll` übernimmt den Besitz von `C:\ProgramData\OpenCM` für die Administratoren und lässt nur SYSTEM und Administratoren zu. Der Dienst startet nicht, wenn Konfiguration oder Datenverzeichnis einem anderen Benutzer gehören (Meldung im Log, dann `opencm-agent enroll` erneut als Administrator ausführen).

### Inventar
| Bereich | Windows | Linux | macOS |
|---|---|---|---|
| Hardware, BIOS, Seriennummer | CIM (Win32_ComputerSystem/BIOS/Processor) | `/sys/class/dmi`, `/proc/cpuinfo`, `/proc/meminfo` | `system_profiler` |
| Betriebssystem | CIM + Registry (DisplayVersion, UBR) | `/etc/os-release`, Kernel | `system_profiler`, `sysctl` |
| Software | Uninstall-Schlüssel (64/32 Bit), MSIX/Store | dpkg, rpm | `system_profiler SPApplicationsDataType` |
| Patches | Win32_QuickFixEngineering | – (folgt mit M5) | `softwareupdate --history` |
| Dienste | Win32_Service | systemd | launchd |
| Autostart | Win32_StartupCommand | XDG-Autostart | – |
| Benutzer/Gruppen | CIM + ADSI (WinNT) | `/etc/passwd`, `/etc/group` | `dscl` |
| Angemeldete Benutzer | Besitzer von explorer.exe (Konsole + RDP) | `who` | Konsolenbenutzer |
| Netzwerk, Datenträger | Go `net` / CIM | Go `net` / `/proc/mounts` + statfs | Go `net` / `df` |

Die Änderungshistorie erfasst Hardware, OS, Software, Patches, Starttyp von Diensten, Autostart, Benutzer, Gruppenmitglieder und Datenträgergröße. Flüchtige Werte (freier Speicher, Dienst-Laufstatus, IP-Adressen, angemeldete Benutzer) werden bewusst nicht protokolliert.

## Skripte & Jobs (M2)

### Ablauf
1. **Skript anlegen** (Web → Skripte, oder API). Jede Änderung erzeugt eine neue, unveränderliche Version (`draft`). Die Datenbank verhindert per Trigger, dass Inhalte nachträglich geändert werden.
2. **Testlauf** auf einem einzelnen Gerät (Recht `scripts:execute`). Die Ausgabe erscheint live. Einen **Entwurf** darf nur testen, wer zusätzlich `scripts:approve` hat: Ein Entwurf ist ungeprüfter Code, und ohne diese Regel ließe sich die Freigabe über Testläufe umgehen.
3. **Freigeben** (`scripts:approve`). Nur freigegebene Versionen dürfen in Jobs und Ad-hoc-Läufen verwendet werden. Der Autor darf seine eigene Version standardmäßig nicht freigeben (`SCRIPT_SELF_APPROVAL=false`). Für Installationen mit nur einem Administrator lässt sich das mit `SCRIPT_SELF_APPROVAL=true` abschalten.
4. **Job** anlegen:
   - Schritte in fester Reihenfolge, mit Parametern, Option „Fehler ignorieren“ und optionalem Ziel-Feld
   - Ziele: Geräte, statische oder dynamische Gruppen, alle Geräte
   - Auslöser: manuell, einmalig, Cron (mit Zeitzone), Agent-Start, Benutzer-Login
   - Optionen: Timeout, Wiederholungen, Pause, Wartungsfenster
5. **Ausführung** verfolgen: Run → Task je Gerät → Live-Ausgabe. Runs lassen sich abbrechen und für fehlgeschlagene Geräte wiederholen.

Per CLI: `opencm scripts run <id> --target group:Buchhaltung --param Days=7 --watch` und `opencm jobs status <run-id> --watch`. Die CLI beendet sich mit Exitcode 7, wenn mindestens ein Gerät fehlgeschlagen ist.

### Skripte schreiben
- Parameter kommen als **Umgebungsvariablen** an, nie als Textersetzung: `$env:OPENCM_PARAM_DAYS` (PowerShell), `%OPENCM_PARAM_DAYS%` (CMD), `$OPENCM_PARAM_DAYS` (bash/zsh), `os.environ["OPENCM_PARAM_DAYS"]` (Python). Daneben gibt es `OPENCM_TASK_ID`, `OPENCM_DEVICE_ID` und `OPENCM_STEP`.
- **Exitcode 0 = Erfolg**, alles andere gilt als Fehler.
- Skripte laufen als **SYSTEM** (Windows) bzw. **root** (Linux/macOS), ohne Benutzerinteraktion, im Arbeitsverzeichnis `<DataDir>/work`.
- Die Ausgabe ist UTF-8. Windows-PowerShell- und CMD-Skripten setzt der Agent dafür eine feste Präambel voran; der signierte Inhalt selbst bleibt unverändert.
- **Eigene Inventarwerte sammeln:** Im Job-Schritt „Ausgabe in Feld speichern“ wählen. Die letzte nicht-leere Zeile der Standardausgabe wird typgeprüft in das Feld geschrieben. Zusammen mit einem Cron-Auslöser entsteht so ein Inventar-Skript.

| Interpreter | Windows | Linux | macOS |
|---|---|---|---|
| PowerShell | `powershell.exe` 5.1 | – | – |
| CMD | `cmd.exe` | – | – |
| bash / zsh | – | `/bin/bash`, `/bin/zsh` | `/bin/bash`, `/bin/zsh` |
| Python 3 | `py -3` / `python` | `python3` | `python3` |

Geräte, deren OS einen Interpreter nicht unterstützt, erhalten den Status `skipped`. Fehlt der Interpreter auf dem Gerät, wird der Task als `failed` gemeldet.

### Sicherheit der Ausführung
- Jeder Auftrag wird mit dem Ed25519-Schlüssel des Servers signiert (`PKI_DIR/signing.key`, im Backup enthalten). Der Agent prüft vor der Ausführung Signatur, Geräte-ID, Ablaufzeit (10 Minuten) und den SHA-256 jedes Schritts. Ein manipulierter Server-Datenbankinhalt reicht deshalb nicht aus, um Code auf Geräten auszuführen; dafür wäre zusätzlich der Signaturschlüssel nötig.
- Die Ausgabe wird pro Task bis `TASK_OUTPUT_MAX_BYTES` gespeichert, der Rest verworfen und markiert.

### Zeitpläne & Worker
- Der **Worker** (Container `worker`) prüft alle 15 s fällige Cron- und Einmal-Jobs, Timeouts (Job-Timeout + `TASK_TIMEOUT_GRACE_SECONDS`) und Wiederholungen. Mehrere Worker sind möglich, jede Ausführung wird trotzdem nur einmal gestartet. Mit eingebetteter Dev-Datenbank (`pglite://`) läuft der Scheduler im Serverprozess.
- **Cron** nutzt 5 Felder und die Zeitzone des Jobs, Sommer- und Winterzeit inklusive. Beispiel: `0 3 * * 1-5` bedeutet werktags um 03:00.
- **Wartungsfenster:** Tasks werden nur innerhalb des Fensters ausgeliefert. Ein Fenster mit Ende ≤ Beginn reicht über Mitternacht (z. B. Mo–Fr 22:00–05:00).
- **Agent-Start / Benutzer-Login:** werden beim Heartbeat ausgewertet, also innerhalb von etwa 60 s.

### Agent-Selbstupdate
Neue Binaries und eine neue `version.txt` nach `/data/files/agent/` kopieren (siehe oben). Agents mit abweichender Version bekommen beim nächsten Heartbeat ein signiertes Update-Angebot. Sie laden das Binary über mTLS, prüfen SHA-256 und Signatur, tauschen es aus und lassen sich vom Dienstmanager neu starten. Während ein Task läuft, wird nicht aktualisiert. Abschalten lässt sich das mit `AGENT_AUTO_UPDATE=false`. Entwickler-Builds (`dev`) werden nie automatisch aktualisiert.

## Schwachstellen (M3)

### Feeds
| Feed | Intervall | Hinweis |
|---|---|---|
| NVD (CVE API 2.0) | 2 h (`NVD_SYNC_INTERVAL_HOURS`) | Der erste Start spiegelt alle ca. 425.000 CVEs, in Etappen von `NVD_MAX_PAGES_PER_RUN` × 2.000 je Worker-Lauf; wird ein Lauf unterbrochen, geht es an derselben Stelle weiter. Ohne API-Schlüssel dauert das ca. 25–40 min (NVD erlaubt 5 Anfragen / 30 s), mit `NVD_API_KEY` (kostenlos bei NIST, nur E-Mail-Adresse nötig) wenige Minuten. Der Spiegel liegt danach in der Datenbank und wird nicht erneut geladen. Danach nur noch Änderungen. |
| CISA KEV | 6 h | Markiert aktiv ausgenutzte CVEs, inkl. CISA-Frist und Ransomware-Bezug |
| FIRST EPSS | 24 h | Nur für CVEs mit offenen Befunden |
| OSV (M7) | jede Minute inkrementell, Neuprüfung je Paketversion nach 24 h (`OSV_SYNC_INTERVAL_HOURS`) | Sicherheitsmeldungen der Linux-Distributionen; siehe „Linux-Distributionspakete (OSV)“ |

- Der Server braucht ausgehenden HTTPS-Zugriff auf `services.nvd.nist.gov`, `www.cisa.gov`, `api.first.org` und `api.osv.dev`. Über einen Proxy: `NODE_USE_ENV_PROXY=1` und `HTTPS_PROXY=http://proxy:3128` setzen.
- Status und Fehler: Web → Schwachstellen → „Feeds“ bzw. `opencm cve summary`. „Jetzt synchronisieren“ fordert einen Lauf an; der Worker startet ihn innerhalb einer Minute.
- Ohne Internetzugang `VULN_FEEDS_ENABLED=false` setzen.

### Wie Befunde entstehen
1. Jede installierte Software wird einem CPE-Produkt (`vendor:product`) zugeordnet: zuerst über **Regeln**, dann per **Heuristik** (Name/Herausgeber gegen die Produkte, für die es in NVD CVEs gibt).
2. Die Version wird gegen die Versionsbereiche der CVEs geprüft.
3. **Konfidenz:**
   - *sicher*: Zuordnung per Regel
   - *wahrscheinlich*: Zuordnung per Heuristik
   - *sicher* mit Kennzeichnung „Distribution“: Sicherheitsmeldung der Linux-Distribution über OSV (siehe unten)
   - *unbestätigt*: Linux-Distributionspaket, das OSV (noch) nicht geprüft hat, z. B. bei nicht unterstützter Distribution. Debian, Ubuntu und RHEL portieren Fixes zurück, ohne die Upstream-Version zu ändern; solche Befunde sind häufig bereits behoben.
4. Neubewertung: nach jedem Feed-Sync und für jedes Gerät mit neuem Inventar (alle 5 min). Behobene Befunde bleiben mit Datum sichtbar.

### Linux-Distributionspakete (OSV)
Für **Debian, Ubuntu (LTS und Zwischenversionen), Rocky Linux und AlmaLinux** fragt OpenCM die freie Datenbank [OSV](https://osv.dev) ab. Sie enthält die Sicherheitsmeldungen der Distributionen mit exakten Paketversionen.
- **Ablauf:** Der Agent (ab 0.8) meldet das Quellpaket (`openssl` statt `libssl3`) und die vollständige Paketversion. Der Worker fragt neue Paketversionen gebündelt ab (1000 je Anfrage), speichert die Antwort und prüft jede Version nach 24 h erneut. „Jetzt synchronisieren“ für den Feed *OSV* prüft sofort alle installierten Versionen.
- **Wirkung:** Ein Paket, das OSV geprüft hat, wird **nicht mehr** über den CPE-Abgleich bewertet. Befunde aus zurückportierten Fixes (z. B. „openssl 3.0.2“ auf einem gepatchten Ubuntu) verschwinden; echte Lücken erscheinen mit Konfidenz *sicher*. Jedes betroffene Binärpaket eines Quellpakets bekommt einen eigenen Befund.
- **CVE-Bezug:** Meldungen werden über ihre CVE-Aliase zugeordnet. Fehlt eine CVE noch im NVD-Spiegel, wird sie mit der Kurzbeschreibung aus OSV angelegt und später von NVD ergänzt. Meldungen ganz ohne CVE werden nicht angezeigt.
- **Datenschutz:** An osv.dev gehen nur Ökosystem, Paketname und Version, nie Hostnamen, IP-Adressen oder Gerätezahlen. Abschalten mit `OSV_ENABLED=false`. Dann gilt für alle Distributionspakete wieder der CPE-Abgleich.
- **Nicht abgedeckt:** RHEL selbst (OSV führt Red-Hat-Meldungen nach Produkt-Streams), SUSE, Alpine, Arch. Für diese Systeme bleibt es bei *unbestätigt*.

**Bewusste Grenzen:** CVE-Kriterien ohne jede Versionsangabe („alle Versionen“) werden übersprungen. Plattform-Bedingungen aus NVD werden ignoriert, was im Zweifel einen Befund mehr ergibt. Betriebssystem-Schwachstellen (Windows, Linux-Kernel) werden mit dem Patch-Management in M5 abgedeckt.

### Zuordnung pflegen
Unter Web → **Software & Zuordnung** (oder `opencm software --mapping unmapped`) ist jede Software mit ihrer Zuordnung sichtbar. Für nicht zugeordnete Software gibt es Vorschläge, die man per Klick als Regel übernimmt. Regeln sind Glob-Muster (`*`, `?`, Groß-/Kleinschreibung egal) auf den vollständigen Namen, optional auf Herausgeber und Quelle. „Ignorieren“ schließt Software aus, z. B. Eigenentwicklungen. Mitgelieferte Regeln lassen sich deaktivieren und durch eigene mit niedrigerer Priorität überschreiben.

### Reagieren
- **Behebungs-Job:** In der CVE-Ansicht wird aus einem freigegebenen Skript ein Job für alle betroffenen Geräte erzeugt. Passende Vorlagen gibt es unter Skripte → „Aus Vorlage“ (winget, Deinstallation per MSI/Registry, Chocolatey, apt, dnf, macOS-Updates). Nach dem nächsten Inventar wechselt der Befund auf „behoben“.
- **Risikoakzeptanz** mit Pflicht-Begründung, flottenweit je CVE, im Audit-Log protokolliert. Akzeptierte CVEs sind standardmäßig ausgeblendet.
- **Webhook** (`VULN_WEBHOOK_URL`) für neue kritische oder aktiv ausgenutzte Befunde. Ist `VULN_WEBHOOK_SECRET` gesetzt, trägt jede Nachricht den Header `X-OpenCM-Signature: sha256=<HMAC-SHA256 des Bodys>`.

## Berechtigungen & Anmeldung (M4)

### Rollen mit Geltungsbereich
Rollen werden Benutzern direkt oder über Benutzergruppen zugewiesen (System → Benutzer → „Rollen“ bzw. System → Gruppen → „Bearbeiten“). Jede Zuweisung gilt entweder **auf alle Geräte** oder **nur auf bestimmte Gerätegruppen**. Beispiel: Die Rolle „Operator“ nur für die Gerätegruppe „Standort Nord“ erlaubt, dort Inventar zu sehen und Skripte auszuführen. Geräte außerhalb des Bereichs sind für diese Person unsichtbar (API: 404).

- Eingeschränkte Zuweisungen wirken nur auf gerätebezogene Rechte: Geräte, Inventar, Schwachstellen, Ad-hoc-Skriptläufe sowie Ausführungen und Ausgaben. Verwaltungsrechte (Benutzer, Rollen, Skripte bearbeiten, Jobs anlegen, Einstellungen) brauchen immer eine globale Zuweisung.
- Niemand kann Rechte vergeben, die er selbst nicht global besitzt.

### Vier-Augen-Prinzip
Massenaktionen werden erst ausgeführt, wenn eine **zweite Person** mit dem Recht `jobs:approve` zustimmt (Web → Freigaben, CLI `opencm approvals list|approve|reject`). Als Massenaktion gilt ein Ziel „Alle Geräte“ oder ab der eingestellten Geräteanzahl (Standard 50, System → Sicherheit). Betroffen sind:
- Job „jetzt ausführen“ und Ad-hoc-Skriptläufe (die API antwortet mit `202` und `approvalId`)
- Behebungs-Jobs mit „sofort ausführen“
- geplante Jobs mit breitem Ziel: sie werden deaktiviert gespeichert und erst mit der Freigabe aktiviert
- das Wiederholen einer Ausführung (`rerun`)

**Aufteilen hilft nicht:** Für die Schwelle zählen auch die Geräte der eigenen Ausführungen der letzten 60 Minuten (`FOUR_EYES_WINDOW_MINUTES`, 0 = jede Anfrage für sich). Wer nacheinander mehrere kleine Läufe startet, braucht ab der Schwelle ebenfalls eine Freigabe. Bereits freigegebene Läufe und Verteilungen zählen nicht mit. Testläufe zählen mit, haben aber keinen Freigabeweg: Ist die Schwelle erreicht, lehnt der Server sie mit `409 four_eyes_limit` ab.

Eigene Anfragen kann man nicht selbst freigeben. Bei der Freigabe wird geprüft, ob die anfragende Person die Rechte noch hat und ob der Job inzwischen geändert wurde. Ablehnen braucht eine Begründung, und offene Anfragen verfallen nach 24 h. Die CLI beendet sich mit **Exitcode 8**, wenn eine Aktion auf Freigabe wartet.

### Zwei-Faktor-Anmeldung (TOTP)
Jeder Benutzer richtet MFA unter seinem Profil ein: QR-Code mit einer Authenticator-App scannen (z. B. Microsoft/Google Authenticator, 2FAS, KeePassXC) und mit einem Code bestätigen. Er erhält dabei 10 Wiederherstellungscodes, die je einmal gültig sind. Ist „MFA für alle verpflichtend“ aktiv, kann ein Benutzer ohne MFA nach der Anmeldung nur die Einrichtung durchführen. Verliert jemand sein Gerät, setzt ein Admin MFA unter System → Benutzer → „MFA zurücksetzen“ zurück. Das TOTP-Geheimnis liegt AES-256-GCM-verschlüsselt in der Datenbank, der Schlüssel unter `PKI_DIR/secrets.key` (im Volume `pki`, also **mit sichern**). CLI: `opencm login --otp 123456` oder interaktive Abfrage.

### API-Tokens
Für Skripte und CI unter Profil → API-Tokens oder mit `opencm tokens create <name> --permission devices:read --days 30`. Ein Token hat höchstens die Rechte seines Besitzers, optional weiter eingeschränkt, und eine maximale Laufzeit (`API_TOKEN_MAX_DAYS`). Benutzt wird es als `Authorization: Bearer oct_…` oder mit `OPENCM_TOKEN=oct_… opencm …`. Der Klartext wird nur einmal angezeigt; gespeichert ist nur ein Hash. Tokens können keine weiteren Tokens erzeugen und keine MFA-Einstellungen ändern.

### LDAP / Active Directory
1. In der `.env` mindestens `LDAP_URL`, `LDAP_BIND_DN`, `LDAP_BIND_PASSWORD` und `LDAP_BASE_DN` setzen (siehe `deploy/.env.example`), dann `docker compose up -d`. Empfohlen ist `ldaps://`. Für eine eigene CA die Zertifikatsdatei in das `pki`-Volume legen und `LDAP_CA_FILE=/data/pki/ldap-ca.pem` setzen.
2. Unter System → Gruppen einer OpenCM-Gruppe die **AD-Gruppe (DN)** zuordnen, z. B. `CN=OpenCM-Admins,OU=Gruppen,DC=firma,DC=local`, und der Gruppe Rollen geben.
3. Unter System → Sicherheit „Verbindung testen“ (optional mit Benutzername) zeigt DN, Name und die aufgelösten Gruppen an.

Bei der Anmeldung wird zuerst ein lokales Konto geprüft, dann das Verzeichnis. Verzeichnisbenutzer werden beim ersten Login angelegt; ihre Gruppenmitgliedschaften werden bei jedem Login abgeglichen, verschachtelte AD-Gruppen eingeschlossen. Mit `LDAP_REQUIRE_GROUP=true` (Standard) dürfen sich nur Mitglieder gemappter Gruppen anmelden. Lokale Konten werden nie von LDAP übernommen, deshalb funktioniert ein lokaler Notfall-Admin auch bei Verzeichnisausfall. Passwörter von Verzeichnisbenutzern werden nur im AD geändert.

### Audit-Export
Web → Audit-Log → „Export CSV/JSON“ oder `opencm audit export --format csv -f audit.csv --since 2026-11-01T00:00:00Z`. Die CSV-Datei ist für Excel aufbereitet: UTF-8 mit BOM, Trennzeichen `;`, und Zellen, die mit `=`, `+`, `-` oder `@` beginnen, werden entschärft. Ein Export enthält höchstens 100.000 Einträge und wird selbst im Audit-Log vermerkt.

## Softwareverteilung (M5)

### Pakete
Web → Softwareverteilung → **Pakete** (CLI `opencm packages …`). Ein Paket hat eine Plattform und Versionen. Jede Version beschreibt:

| Typ | Plattform | Quelle |
|---|---|---|
| MSI, EXE | Windows | hochgeladene Datei (EXE braucht Silent-Parameter, z. B. `/S`) |
| winget, Chocolatey | Windows | Paket-ID (winget wird im SYSTEM-Kontext automatisch gefunden, Chocolatey muss installiert sein) |
| DEB, RPM | Linux | hochgeladene Datei + Paketname (für die Deinstallation) |
| apt, dnf | Linux | Paketname aus den konfigurierten Repositories |
| PKG | macOS | hochgeladene Datei |
| Homebrew | macOS | Formel; läuft im Kontext des angemeldeten Benutzers, denn brew verweigert root |
| Eigene Befehle | alle | PowerShell- bzw. bash-Befehl; eine hochgeladene Datei steht in `OPENCM_FILE_1` |

- **Erkennungsregeln** legen fest, wann ein Paket als installiert gilt. Regeltypen: Software (Name mit `*` und optional Version ≥ / = / <), Datei, Registry (Windows) und Befehl (Exitcode 0). Alle Regeln müssen zutreffen.
  - Vor der Installation: Wird das Paket schon erkannt, passiert nichts.
  - Nach der Installation: Wird es nicht erkannt, gilt der Lauf als fehlgeschlagen, auch wenn der Installer 0 meldet.
  - Software-Regeln liefern zusätzlich den **Installationsstand** aus dem Inventar.
- **Exitcodes:** Erfolg ist standardmäßig `0`. `3010` und `1641` gelten als „erfolgreich, Neustart nötig“. Neustarts löst OpenCM nicht aus, sie erscheinen nur als `OPENCM-REBOOT-REQUIRED` in der Ausgabe.
- **Freigabe** wie bei Skripten: Nur freigegebene Versionen sind verteilbar, und sie sind danach unveränderlich (zusätzlich per DB-Trigger erzwungen). Mit `SCRIPT_SELF_APPROVAL=false` muss eine zweite Person freigeben. Unter „Erzeugtes Installationsskript“ ist genau das Skript zu sehen, das auf den Geräten läuft.
- **Repository:** Dateien liegen inhaltsadressiert unter `/data/files/packages/<sha256>` im Volume `files`. Gleiche Dateien werden nur einmal gespeichert. Die Maximalgröße steuert `PACKAGE_MAX_BYTES`.

### Verteilung in Ringen
Paket → **Verteilen …** bzw. `opencm deploy 7-Zip --ring Test=group:IT --ring Pilot=group:Pilot --ring Alle=all --delay 24 --min-success 90`.

1. Ring 1 startet sofort. Es zählen nur Geräte der passenden Plattform.
2. Der nächste Ring startet automatisch, wenn der vorige abgeschlossen ist, die Wartezeit vorbei ist und die Erfolgsquote erreicht wurde.
3. Liegt die Quote darunter, wird die Verteilung **angehalten**. Dann mit „Nächsten Ring jetzt starten“ fortfahren oder abbrechen.
4. Geräte, die schon in einem früheren Ring dran waren, bekommen den Auftrag kein zweites Mal. Einzelne fehlgeschlagene Geräte lassen sich in der Ausführung über „Fehlgeschlagene wiederholen“ erneut starten.

Verteilungen auf „alle Geräte“ oder ab der Vier-Augen-Schwelle brauchen eine Freigabe mit `software:approve` (bei Updates `patches:approve`). Wartungsfenster und Wiederholungen wie bei Jobs lassen sich über die API setzen (`options`).

### Bandbreite
Installationsdateien laden die Agents über die mTLS-Verbindung (`/agent/v1/files/<sha256>`, abgebrochene Downloads werden fortgesetzt). Begrenzung: `PACKAGE_BANDWIDTH_KBPS` gilt für alle Downloads zusammen, `PACKAGE_BANDWIDTH_PER_DEVICE_KBPS` je Gerät. Bei 1.000 Geräten und 200 MB pro Paket empfiehlt sich zusätzlich, die Ringe zu staffeln.

## Patch-Management (M5)
- **Scan:** Online-Geräte werden alle `PATCH_SCAN_INTERVAL_HOURS` Stunden automatisch gescannt, manuell über Patches → „Jetzt scannen“ oder in der Geräteansicht → Updates.
  - Windows nutzt den Windows Update Agent, also Microsoft Update oder den per GPO konfigurierten WSUS.
  - Linux nutzt apt (Sicherheitsupdates aus `*-security`) bzw. dnf/yum (`updateinfo`).
  - macOS nutzt `softwareupdate`; als „Sicherheit“ gelten die von Apple empfohlenen Updates.
- **Berichte:** Patches zeigt Kacheln (Sicherheitsupdates, Neustart ausstehend, nie gescannt, Scan fehlgeschlagen) sowie die Ansichten Geräte und Updates. Export als CSV (`opencm patches export -f patchstand.csv`).
- **Installation:** „Updates installieren …“ bzw. `opencm patches install --classification security --ring Test=group:IT --ring Alle=all --delay 24`.
  - Auswahl: kritische Updates, Sicherheitsupdates, alle (ohne Treiber und Funktionsupgrades) oder einzelne Updates (KB, Paketname).
  - Neustart „nie“ oder „bei Bedarf“; Windows warnt 5 Minuten vorher, Linux nutzt `shutdown -r +5`.
  - Es gelten dieselben Ringe wie bei Paketen. Nach der Installation wird automatisch neu gescannt.
- **Grenzen:** Auf Apple-Silicon-Macs können Betriebssystem-Updates eine Bestätigung durch den Benutzer verlangen. Einen eigenen Update-Katalog gibt es nicht; die Updates kommen aus Microsoft Update/WSUS bzw. den Paketquellen der Geräte.

## Dashboard, Berichte, Webhooks, Softwarelizenzen (M6)

### Dashboard
Die Startseite zeigt Kennzahlen je Bereich. Sichtbar sind nur Bereiche, für die man ein Leserecht hat, und bei eingeschränkten Rollen nur Geräte im eigenen Geltungsbereich.
- **Kacheln:** Geräte, aktiv ausgenutzte und kritische Schwachstellen, Sicherheitsupdates, fehlgeschlagene Tasks, Hash-Verstöße, Verteilungen, Freigaben, Softwarelizenzen.
- **Verlauf:** Der Worker speichert stündlich die Tageswerte (`metrics_daily`, Aufbewahrung `METRICS_RETENTION_DAYS`). Trends erscheinen ab dem zweiten Tag und nur für Benutzer mit globalem Leserecht des Bereichs.

### Berichte
Übersicht → **Berichte** → „Neuer Bericht“: Quelle wählen (Geräte, installierte Software, Schwachstellen-Befunde, ausstehende Updates, Task-Ergebnisse, Softwarelizenzen), dann Spalten, Filter (alle müssen zutreffen) und Sortierung; die Vorschau aktualisiert sich. Berichte sind privat oder für alle mit `reports:read` geteilt.
- Export als CSV (Excel-tauglich, bis 100.000 Zeilen) oder JSON.
- CLI: `opencm reports query software --filter "name contains firefox" --filter "version lt 130"` und `opencm reports run <id> --csv datei.csv`.
- Rechte: `reports:*` und zusätzlich das Leserecht der Quelle. Gerätebezogene Quellen werden auf den Geltungsbereich gefiltert.
- Sicherheit: Es wird kein SQL vom Client angenommen; Spalten und Operatoren sind feste Listen, Werte werden als Parameter gebunden.

### Webhooks
System → **Webhooks**: URL (https) und Ereignisse wählen. Das Geheimnis wird einmal angezeigt.

| Ereignis | Wann |
|---|---|
| `device.enrolled` | neues oder neu registriertes Gerät |
| `run.completed` / `task.failed` | Ausführung beendet / Task endgültig fehlgeschlagen |
| `deployment.completed` / `deployment.paused` | Verteilung fertig / angehalten (Quote, Hash-Fehler) |
| `approval.requested` | Vier-Augen-Freigabe angefordert |
| `vulnerability.findings.new` | neue kritische oder aktiv ausgenutzte Befunde |
| `patch.scan_failed` | Patch-Scan fehlgeschlagen |
| `security.integrity_violation` | Hash-Prüfung fehlgeschlagen |
| `license.overused` | Softwarelizenz überschritten |
| `device.security_changed` | Sicherheitsstatus eines Geräts verschlechtert (neue Probleme, z. B. BitLocker aus) – M7 |

- **Nachricht:** `POST` mit JSON `{ id, event, occurredAt, data }` und den Headern `X-OpenCM-Event`, `X-OpenCM-Delivery` und `X-OpenCM-Timestamp`.
- **Signatur:** `X-OpenCM-Signature: sha256=<HMAC-SHA256(Geheimnis, Timestamp + "." + Body)>`. Der Empfänger sollte die Signatur prüfen und alte Zeitstempel (> 5 min) verwerfen.
- **Zustellung:** über eine Outbox in der Datenbank. Wiederholungen nach 1 min, 5 min, 30 min, 2 h und 6 h, danach `failed`. Fehlgeschlagene Zustellungen lassen sich im Protokoll „erneut senden“.
- **Einschränkungen:** Ziele mit Link-Local- oder Cloud-Metadaten-Adressen (169.254.0.0/16, fe80::/10) werden abgewiesen, auch wenn ein Hostname dorthin auflöst. `http://` ist nur mit `WEBHOOK_ALLOW_HTTP=true` erlaubt. Interne Systeme wie Ticketsystem oder Chat bleiben erreichbar.
- Der Webhook `VULN_WEBHOOK_URL` aus M3 funktioniert weiter. Neu eingerichtet werden sollte über die Webhook-Verwaltung.

### Softwarelizenzen
Softwareverteilung → **Softwarelizenzen**: Hier wird erfasst, wie viele Lizenzen die Organisation für eine Software besitzt (z. B. „Microsoft 365 Apps*“, 120 Stück, gültig bis 30.06.2027).
- OpenCM zählt die aktiven Geräte, auf denen die Software laut Inventar installiert ist. Angezeigt werden: genutzt / frei / **überschritten** sowie Verträge, die in 30 Tagen oder früher ablaufen.
- Bei Überschreitung wird `license.overused` gemeldet.
- Das Modul hat **nichts mit der Lizenz von OpenCM zu tun**: OpenCM ist Open Source (MIT-Lizenz, siehe `LICENSE`), ohne Beschränkung von Geräten oder Funktionen.

## Sicherheitsstatus der Geräte (M7)
Sicherheit → **Sicherheitsstatus** zeigt für jedes Gerät, ob die Grundschutz-Maßnahmen greifen. Der Agent (ab 0.8) meldet die Daten mit jedem Inventar; die Abfragen sind rein lesend.

| Bereich | Windows | macOS | Linux |
|---|---|---|---|
| Verschlüsselung | BitLocker je Laufwerk (`Win32_EncryptableVolume`, inkl. „angehalten“) | FileVault (`fdesetup`) | LUKS/dm-crypt unter den eingehängten Dateisystemen (`lsblk`); `/boot` und EFI-Partition zählen nicht |
| Virenschutz | Microsoft Defender (`Get-MpComputerStatus`) und im Sicherheitscenter registrierte Fremdprodukte | XProtect + Gatekeeper | Defender für Linux (`mdatp`), ClamAV – optional |
| Firewall | Profile Domäne/Privat/Öffentlich | Programm-Firewall | ufw, firewalld oder nftables |
| Secure Boot / TPM | ja / ja | – | Secure Boot (efivars/mokutil), TPM (`/sys/class/tpm`) |

- **Konform** ist ein Gerät, wenn alle Laufwerke verschlüsselt sind, die Firewall an ist und unter Windows und macOS ein Virenschutz aktiv, mit Echtzeitschutz und aktuell ist. Signaturen gelten als veraltet nach `SECURITY_AV_MAX_AGE_DAYS` (Standard 3 Tage, für XProtect mindestens 30). Secure Boot und TPM werden angezeigt und gemeldet, zählen aber nicht zur Konformität.
- **„Unbekannt“** heißt, der Wert ließ sich nicht ermitteln, etwa wenn die BitLocker-Funktion auf einem Server nicht installiert ist oder ein Werkzeug fehlt. Unbekannte Verschlüsselung oder Firewall gilt als nicht konform.
- **Geräte ohne Daten** laufen mit einem älteren Agent oder haben noch kein Inventar geschickt. Nach dem Agent-Selbstupdate kommt der Status mit dem nächsten Inventar.
- **Probleme** haben feste Codes (z. B. `unencrypted`, `encryption_suspended`, `av_outdated`, `firewall_off`). Sie lassen sich filtern, als CSV exportieren und per Webhook `device.security_changed` melden (nur bei Verschlechterung).
- **Gruppen:** Dynamische Gerätegruppen filtern nach `Verschlüsselung`, `Virenschutz`, `Firewall` und `Sicherheitsstatus konform`, z. B. „alle Notebooks mit Verschlüsselung ≠ verschlüsselt“. Solche Gruppen eignen sich als Ziel für einen Job, der BitLocker aktiviert.

## Assets ohne Agent (M7)
Geräte → **Assets** verwaltet Geräte, auf denen kein Agent läuft: Monitore, Drucker, Telefone, Netzwerkgeräte, Dockingstationen oder Geräte im Lager.
- **Felder:** Typ, Status (Lager, in Benutzung, Reparatur, ausgemustert), Hersteller, Modell, Seriennummer, Inventarnummer (eindeutig), Standort, Person, IP- und MAC-Adresse, Kaufdatum, Garantie bis, Kosten und Notizen.
- **Zuordnung:** Ein Asset kann einem verwalteten Gerät zugeordnet werden. Es erscheint dann im Geräte-Reiter „Zubehör“.
- **CSV-Import:**
  - Spalten mit deutschen oder englischen Namen, getrennt durch `;` oder `,`. Eine Vorlage steht auf der Seite zum Download.
  - Ein Probelauf zeigt neue, aktualisierte und fehlerhafte Zeilen, ohne etwas zu ändern.
  - Abgleich über die Inventarnummer, sonst über die Seriennummer.
  - Fehlerhafte Zeilen werden übersprungen und mit Zeilennummer gemeldet. Unbekannte Geräte-Hostnamen ergeben nur einen Hinweis.
  - CLI: `opencm assets import datei.csv --dry-run`.
- **CSV-Export:** gleiche Spalten wie der Import, also wieder einlesbar.
- **Garantie:** Filter „läuft in 30/90 Tagen ab“, Dashboard-Kachel, Berichtsquelle „Assets“ mit der Spalte „Garantie (Tage übrig)“.
- **Rechte:** Modul `assets` (lesen/anlegen/ändern/löschen). Der Import braucht `assets:create` und `assets:update`.

## Manipulationsschutz (Hash-Prüfung)
Alles, was auf einem Gerät ausgeführt wird, erhält beim Speichern einen **SHA-256-Hash**: Skriptversionen, hochgeladene Installationsdateien und die für Pakete und Patches erzeugten Schritte. Vor der Ausführung wird mehrfach 1:1 verglichen:

| Wann | Prüfung |
|---|---|
| Lauf anlegen (Job, Ad-hoc, Verteilungsring, Patch-Scan) | Inhalt ↔ gespeicherter Hash ↔ Quelle (freigegebene Skriptversion bzw. Paketversion) ↔ Siegel |
| Auslieferung an das Gerät | dieselbe Prüfung noch einmal; der Auftrag wird mit Ed25519 signiert |
| Freigabe einer Paketversion und Start jedes Rings | Installationsdatei im Repository neu gehasht |
| Auf dem Gerät (Agent) | Signatur, Hash jedes Schritts, Hash der heruntergeladenen Datei und der Skriptdatei auf dem Datenträger direkt vor dem Start |

**Siegel:** Wer Schreibzugriff auf die Datenbank hat, könnte Inhalt und Hash gemeinsam ändern. Deshalb ist jeder Hash zusätzlich mit einem HMAC versiegelt. Der Schlüssel liegt nur in `PKI_DIR/integrity.key` im Volume `pki`, nicht in der Datenbank. Der Worker bindet das Volume schreibgeschützt ein. Den Schlüssel **mit sichern**, sonst gelten nach einem Restore alle Siegel als ungültig.

**Bei Abweichung** wird nichts ausgeführt:
- Der Task endet mit Status `failed`, und der Fehler beginnt mit `integrity:`. Im Web erscheint das rote Kennzeichen „Hash-Prüfung fehlgeschlagen“, in der Ausgabe steht „ABGEBROCHEN – Hash-Prüfung fehlgeschlagen“.
- Es gibt keine automatische Wiederholung, und die folgenden Schritte laufen nicht.
- Verteilungen werden pausiert und nennen den Grund.
- Jeder Fall erzeugt den Audit-Eintrag `security.integrity_violation` mit dem Feld `detectedBy` (`server`, `agent` oder `repository`). Filter: Audit-Log → Aktion `security.integrity_violation`.

## Backup & Restore
`deploy/backup.sh` (DB-Dump + Volumes `files` und `pki`) und `deploy/restore.sh <dir> --yes`.

## Updates
`docker compose pull && docker compose up -d`. Migrationen laufen beim Serverstart automatisch.
