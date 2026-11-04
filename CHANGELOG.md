# Changelog

Alle nennenswerten Änderungen an diesem Projekt. Format nach [Keep a Changelog](https://keepachangelog.com/de/1.1.0/), Versionen nach [SemVer](https://semver.org/lang/de/).

## [Unreleased]

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
