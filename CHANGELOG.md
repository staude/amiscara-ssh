# Changelog

Alle nennenswerten Änderungen an diesem Projekt. Format nach [Keep a Changelog](https://keepachangelog.com/de/1.1.0/), Versionen nach [SemVer](https://semver.org/lang/de/).

## [Unreleased]

### Added

- Jump-Host-Ketten: `Session::connect_via` öffnet eine Verbindung über einen `direct-tcpip`-Kanal einer anderen Sitzung, ohne lokalen Port. `Route` beschreibt beliebig viele Sprünge, jeder mit eigenem Benutzer, eigenen Zugangsdaten und eigenem Host-Key (staude/amiscara-connect#25).
- `SessionPool` mit einer geteilten Verbindung pro Sprung: Schlüssel ist der Weg bis zum Sprung, gezählt werden `Lease`s und Verbindungen dahinter, die letzte Rückgabe schließt die Verbindung. `connect_fresh` baut nur zum Ziel neu auf. Tote Sprünge werden beim nächsten `connect` ab dort ersetzt, Zeitgrenze und Keepalive je Sprung (`PoolConfig`).
- Status je Sprung als `HopEvent` (`subscribe`): verbinden, verbunden mit Aufbauzeit, wiederverwendet, fehlgeschlagen mit `HopFailure`, geschlossen. Fehler eines Sprungs als `SshError::Hop` mit Index, neu `SshError::Timeout`.
- Agent-Forwarding über `SshTarget::agent_forward`, standardmäßig aus; im Pool nur für das Ziel, nie für einen Sprung. Ohne Einschalten lehnt der Client Agent-Kanäle des Servers ab.
- Host-Key-Prüfung durch die App: `HostKeyPolicy::Verifier` mit dem Trait `HostKeyVerifier` entscheidet während des Handshakes über `HostKeyVerdict` (`Trusted`, `Unknown`, `Changed`); abgelehnt wird mit `SshError::UnknownHostKey` bzw. `SshError::HostKeyChanged`. So prüft Connect jeden Sprung gegen die Keys im eigenen Dokument und lernt bei TOFU im selben Aufbau (staude/amiscara-connect#27).
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

[Unreleased]: https://github.com/staude/amiscara-ssh/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/staude/amiscara-ssh/releases/tag/v0.1.0
