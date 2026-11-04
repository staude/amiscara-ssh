# Changelog

Alle nennenswerten Änderungen an diesem Projekt. Format nach [Keep a Changelog](https://keepachangelog.com/de/1.1.0/), Versionen nach [SemVer](https://semver.org/lang/de/).

## [Unreleased]

### Added

- Repo mit Lizenz, Cargo-Gerüst und CI.
- `Session::connect` mit Anmeldung per Schlüsseldatei (auch verschlüsselt), SSH-Agent, Schlüssel im Speicher und Passwort; Keepalive alle 15 s.
- Host-Key-Prüfung über `known_hosts` mit TOFU oder festen Schlüssel, mit `SshError::UnknownHostKey` und `SshError::HostKeyChanged`.
- Shell mit PTY und Fenstergröße (`Session::open_shell`, `Shell::resize`), Kanäle `direct-tcpip` und `direct-streamlocal`.
- Schlüssel erzeugen, lesen und Fingerprint (`keys`), aus `herdr-transport` von Amiscara Agents übernommen.
- Lokaler SSH-Testserver (`scripts/ssh-testserver.sh`) und Container-Tests, in der CI als eigener Job.
