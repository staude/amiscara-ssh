# Changelog

Alle nennenswerten Änderungen an diesem Projekt. Format nach [Keep a Changelog](https://keepachangelog.com/de/1.1.0/), Versionen nach [SemVer](https://semver.org/lang/de/).

## [Unreleased]

### Added

- ProxyCommand: `Session::connect_command` startet einen lokalen Befehl (auf Unix `/bin/sh -c "exec …"`, auf Windows `cmd.exe /S /C "…"`) und führt die Verbindung über dessen stdin und stdout; `Route::proxy_command` tut das für den ersten Sprung einer Kette. Platzhalter `%h`, `%p`, `%r` und `%%` wie in OpenSSH; ein unbekannter Platzhalter und ein Host oder Benutzer mit Zeichen, die in einer Befehlszeile gefährlich sind, werden vor dem Start abgelehnt. Endet der Befehl vor der Anmeldung, nennt der Fehler Exit-Status und Fehlerausgabe, nie den Befehl (wiederholt die Fehlerausgabe ihn, wird er dort ersetzt), auch wenn ein von ihm gestarteter Prozess stdout offen hält. Endet die Verbindung, endet auch der Befehl, nach einer Sekunde Schonfrist, auf Windows samt dem Baum unter `cmd.exe` (staude/amiscara-connect#28).
- `PoolConfig::proxy_connect_timeout` (120 s) als Zeitgrenze für einen ersten Sprung über einen Befehl.
- Tests: Befehl, der vor der Anmeldung endet, und Ende des Befehls nach dem Abbruch (ohne Container, alle Systeme), Sitzung und Pool über `nc %h %p`, Ende des Befehls nach dem Drop, Bastion über einen Befehl in der Testkette.

### Changed

- Neue Varianten `SshError::ProxyCommand` und `HopFailure::ProxyCommand`, neue Felder `Route::proxy_command` und `PoolConfig::proxy_connect_timeout`; wer `Route` selbst aufbaut, ergänzt `proxy_command: None` (oder nutzt `Route::direct`), bei `PoolConfig` `..PoolConfig::default()`. `Debug` von `Route` zeigt den Befehl nicht.
- Der Testserver der Container-Tests lässt parallele Anmeldungen zu (`MaxStartups 100`) und bestraft die Quelle nach dem absichtlich falschen Passwort nicht mehr (`PerSourcePenalties no`); vorher brach sshd parallele Tests gelegentlich mit `Disconnect` ab.

## [0.5.0] - 2026-11-09

### Added

- Einmalcodes per keyboard-interactive: `SshTarget::keyboard_interactive` nimmt ein `KeyboardInteractive`, das die Fragen des Servers als `KeyboardPrompt` bekommt (Weg, Index des fragenden Sprungs, Fragen mit `echo`, Versuch) und mit `KeyboardAnswer` oder `None` für Abbruch antwortet. Gefragt wird nur, wenn der Server Schlüssel, Agent oder Passwort als Teilerfolg angenommen hat und danach noch keyboard-interactive verlangt, nie nach einer Ablehnung; ein abgelehnter Code wird auf derselben Verbindung neu erfragt, höchstens drei Versuche (staude/amiscara-connect#26).
- `HopState::AwaitingInput` während der Frage; die Wartezeit zählt nicht zu `PoolConfig::connect_timeout` und nicht zur Latenz.
- Offenhalten im Pool: Ein Sprung, der gefragt hat, bleibt nach der letzten `Lease` offen, so lange wie `KeyboardAnswer::keep_open` sagt, sonst `PoolConfig::code_grace` (60 s). `SessionPool::close_idle` schließt alle ungenutzten Verbindungen sofort.
- Testkette mit `otp-bastion` (Schlüssel, dann TOTP-Code über PAM) und Tests für Frage, Offenhalten, Abbruch, Neuaufbau hinter der Bastion, Neustart der Bastion, falschen Code und Zeitgrenze.

### Changed

- `SshTarget` hat das neue Feld `keyboard_interactive`, `PoolConfig` das Feld `code_grace`; wer sie selbst aufbaut, ergänzt `keyboard_interactive: None` bzw. `..PoolConfig::default()`.
- Neue Varianten `SshError::Cancelled`, `HopState::AwaitingInput` und `HopFailure::Cancelled`; wer vollständig darauf matcht, ergänzt sie. `SshError::Cancelled` zählt zu `needs_user`.
- Mit dem Agent zählt ein Schlüssel, den der Server nur als Teilerfolg annimmt, jetzt als Anmeldung mit Rest, statt die übrigen Schlüssel zu probieren.

## [0.4.0] - 2026-11-07

### Added

- SFTP: `Session::open_sftp` startet das Subsystem `sftp` auf einem neuen Kanal, auch hinter Jump Hosts, und gibt eine `russh_sftp::client::SftpSession` zurück; `russh_sftp` wird mit exportiert. Neuer Fehler `SshError::SftpUnavailable` (staude/amiscara-connect#29).
- Container-Test für Anlegen, Schreiben, Lesen, Umbenennen und Löschen per SFTP, Test über zwei Sprünge in der Testkette; deren Server bieten jetzt `internal-sftp` an.

### Changed

- `SshError` hat die neue Variante `SftpUnavailable`; wer vollständig darauf matcht, ergänzt sie.

## [0.3.0] - 2026-11-05

### Added

- Host-Key-Prüfung durch die App: `HostKeyPolicy::Verifier` mit dem Trait `HostKeyVerifier` entscheidet während des Handshakes über `HostKeyVerdict` (`Trusted`, `Unknown`, `Changed`); abgelehnt wird mit `SshError::UnknownHostKey` bzw. `SshError::HostKeyChanged`. So prüft Connect jeden Sprung gegen die Keys im eigenen Dokument und lernt bei TOFU im selben Aufbau (staude/amiscara-connect#27).

## [0.2.0] - 2026-11-05

### Added

- Jump-Host-Ketten: `Session::connect_via` öffnet eine Verbindung über einen `direct-tcpip`-Kanal einer anderen Sitzung, ohne lokalen Port. `Route` beschreibt beliebig viele Sprünge, jeder mit eigenem Benutzer, eigenen Zugangsdaten und eigenem Host-Key (staude/amiscara-connect#25).
- `SessionPool` mit einer geteilten Verbindung pro Sprung: Schlüssel ist der Weg bis zum Sprung, gezählt werden `Lease`s und Verbindungen dahinter, die letzte Rückgabe schließt die Verbindung. `connect_fresh` baut nur zum Ziel neu auf. Tote Sprünge werden beim nächsten `connect` ab dort ersetzt, Zeitgrenze und Keepalive je Sprung (`PoolConfig`).
- Status je Sprung als `HopEvent` (`subscribe`): verbinden, verbunden mit Aufbauzeit, wiederverwendet, fehlgeschlagen mit `HopFailure`, geschlossen. Fehler eines Sprungs als `SshError::Hop` mit Index, neu `SshError::Timeout`.
- Agent-Forwarding über `SshTarget::agent_forward`, standardmäßig aus; im Pool nur für das Ziel, nie für einen Sprung. Ohne Einschalten lehnt der Client Agent-Kanäle des Servers ab.
- Testkette aus drei Containern (`scripts/ssh-testkette.sh`) mit eigenem Host-Key je Sprung und Tests in `tests/chain.rs`, in der CI als eigener Job.

### Changed

- `SshTarget` hat das neue Feld `agent_forward`; wer die Struktur selbst aufbaut, ergänzt `agent_forward: false`.

## [0.1.0] - 2026-11-04

### Added

- Repo mit Lizenz, Cargo-Gerüst und CI.
- `Session::connect` mit Anmeldung per Schlüsseldatei (auch verschlüsselt), SSH-Agent, Schlüssel im Speicher und Passwort; Keepalive alle 15 s.
- Host-Key-Prüfung über `known_hosts` mit TOFU oder festen Schlüssel, mit `SshError::UnknownHostKey` und `SshError::HostKeyChanged`. TOFU lernt nur bei Hosts ohne Eintrag, Hostnamen klein geschrieben wie bei OpenSSH, eine unlesbare Datei ist ein Fehler; `trust_host_key` trägt einen bestätigten, unbekannten Schlüssel ein.
- Shell mit PTY und Fenstergröße (`Session::open_shell`, `Shell::resize`), Ende per Exit-Status oder Signal, Kanäle `direct-tcpip` und `direct-streamlocal`.
- Schlüssel erzeugen, lesen und Fingerprint (`keys`), aus `herdr-transport` von Amiscara Agents übernommen.
- Lokaler SSH-Testserver (`scripts/ssh-testserver.sh`) und Container-Tests, in der CI als eigener Job.

[Unreleased]: https://github.com/staude/amiscara-ssh/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/staude/amiscara-ssh/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/staude/amiscara-ssh/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/staude/amiscara-ssh/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/staude/amiscara-ssh/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/staude/amiscara-ssh/releases/tag/v0.1.0
