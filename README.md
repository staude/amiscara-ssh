# amiscara-ssh

Gemeinsamer SSH-Client der Amiscara-Apps ([Amiscara Connect](https://github.com/staude/amiscara-connect) und [Amiscara Agents](https://github.com/staude/amiscara-agents)), gebaut auf [russh](https://github.com/Eugeny/russh).

Ins Crate gehört alles, was nur SSH ist: Verbindungsaufbau und Anmeldung, Host-Key-Prüfung mit TOFU, Schlüssel, Kanäle für Shell mit PTY, `direct-tcpip` und `direct-streamlocal`, Jump-Host-Ketten mit Sitzungs-Pool und Agent-Forwarding, SFTP über `Session::open_sftp`. Was zu einer App gehört, bleibt in der App.

## Einbinden

Die Apps binden das Crate als Git-Abhängigkeit mit festem Tag ein:

```toml
amiscara-ssh = { git = "https://github.com/staude/amiscara-ssh", tag = "v0.3.0" }
```

Wer Crate und App zugleich ändert, setzt in der App lokal eine nicht eingecheckte `.cargo/config.toml`:

```toml
[patch."https://github.com/staude/amiscara-ssh"]
amiscara-ssh = { path = "../amiscara-ssh" }
```

## Entwickeln

- Bauen: `cargo build`
- Tests: `cargo test`, Lint: `cargo clippy --all-targets -- -D warnings`, Format: `cargo fmt`
- Tests gegen den lokalen SSH-Container (braucht Docker):

  ```sh
  scripts/ssh-testserver.sh start
  cargo test -- --ignored
  scripts/ssh-testserver.sh stop
  ```

  Der Server läuft auf `127.0.0.1:2222` (anderer Port über `AMISCARA_SSH_TEST_PORT`), Nutzer `tester`, Schlüssel in `target/ssh-testserver/`. Tests laufen nie gegen fremde oder produktive Server.
- Tests gegen die Jump-Host-Kette (braucht Docker): `scripts/ssh-testkette.sh run` startet Bastion, Jump und Ziel als Container, einen eigenen `ssh-agent` mit dem Testschlüssel, führt `cargo test --test chain -- --ignored` aus und baut alles wieder ab, auch bei Fehlern. Nur die Bastion ist erreichbar, auf `127.0.0.1:2223` (anderer Port über `AMISCARA_SSH_CHAIN_PORT`); jeder Sprung hat eigenen Benutzer, eigene Zugangsdaten und eigenen Host-Key, alles in `target/ssh-testkette/`. `start` und `stop` gibt es auch einzeln.

## Beispiel

```rust
use amiscara_ssh::{HostKeyPolicy, Identity, PtySize, Session, ShellEvent, SshTarget};

// in einer async-Funktion, `home` ist das Home-Verzeichnis
let target = SshTarget {
    host: "example.org".into(),
    port: 22,
    user: "deploy".into(),
    identity: Identity::Agent,
    host_key: HostKeyPolicy::KnownHostsFile {
        path: home.join(".ssh/known_hosts"),
        accept_new: true,
    },
    agent_forward: false,
};
let session = Session::connect(&target).await?;
let mut shell = session.open_shell("xterm-256color", PtySize { cols: 80, rows: 24 }).await?;
shell.write(b"uptime\n").await?;
while let Some(ShellEvent::Output(bytes)) = shell.next().await {
    print!("{}", String::from_utf8_lossy(&bytes));
}
```

## Jump-Host-Ketten

Ein `Route` besteht aus den Sprüngen in Reihenfolge und dem Ziel. Jeder Sprung ist ein eigenes `SshTarget` mit Benutzer, Zugangsdaten und Host-Key; den Namen löst der Sprung davor auf, und unter diesem Namen steht auch der Host-Key in `known_hosts`. Der `SessionPool` hält pro Sprung eine Verbindung, solange eine `Lease` oder eine Verbindung dahinter sie nutzt.

```rust
use amiscara_ssh::{HopState, PoolConfig, PtySize, Route, SessionPool, SshTarget};

// bastion, jump und target sind SshTarget wie oben
let pool = SessionPool::new(PoolConfig::default());
let mut events = pool.subscribe();
let route = Route { jumps: vec![bastion, jump], target };
let session = pool.connect(&route).await?; // zweiter Aufruf: Sprünge wiederverwendet
let shell = session.open_shell("xterm-256color", PtySize { cols: 80, rows: 24 }).await?;
while let Ok(event) = events.try_recv() {
    // z. B. "jump-user@jump:22: Connected { latency: 12ms }"
    println!("{}: {:?}", event.route[event.index], event.state);
}
```

- `connect_fresh` baut nur zum Ziel eine eigene Verbindung auf, die Sprünge kommen weiter aus dem Pool.
- Scheitert ein Sprung, liefert `connect` `SshError::Hop` mit Index und `user@host:port`, das Ereignis `HopState::Failed` nennt die Fehlerart (`HopFailure`).
- `agent_forward: true` am Ziel gibt Shells dort den lokalen SSH-Agent. Sprünge bekommen ihn nie, auch wenn ihr `SshTarget` es verlangt.
- Eine `Lease` gibt man durch Fallenlassen zurück, nicht mit `disconnect()`: das schlösse die geteilte Verbindung für alle. Auch ein abgebrochenes `connect` hinterlässt nichts im Pool.
- Der Pool-Schlüssel ist der Weg aus Host, Port und Benutzer je Sprung (beim Ziel auch `agent_forward`). Zugangsdaten und Host-Key-Regel gehören nicht dazu: Eine lebende Verbindung wird so weiterbenutzt, wie sie angemeldet und geprüft wurde.

## SFTP

`Session::open_sftp` startet das Subsystem `sftp` auf einem neuen Kanal, auch auf einer `Lease` hinter Jump Hosts, und gibt eine `russh_sftp::client::SftpSession` zurück. Das Crate exportiert `russh_sftp` mit, damit die Apps dieselbe Version nutzen.

```rust
let sftp = session.open_sftp().await?;
for entry in sftp.read_dir(".").await? {
    println!("{}", entry.file_name());
}
```

- Die SFTP-Sitzung hält die Verbindung nicht selbst: Die `Session` bzw. `Lease` muss leben, solange sie benutzt wird.
- Ein Server ohne SFTP endet in `SshError::SftpUnavailable`.

## Release

SemVer ab `0.1.0`. Solange 0.x gilt, bricht eine neue Minor-Version die Schnittstelle. Ablauf: PR mit Eintrag in `CHANGELOG.md`, Squash-Merge, `[Unreleased]` zur neuen Version machen, Tag `v<version>` pushen.

## Lizenz

MIT oder Apache-2.0, nach Wahl: [LICENSE-MIT](LICENSE-MIT), [LICENSE-APACHE](LICENSE-APACHE).
