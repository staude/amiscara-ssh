# amiscara-ssh

Gemeinsamer SSH-Client der Amiscara-Apps ([Amiscara Connect](https://github.com/staude/amiscara-connect) und [Amiscara Agents](https://github.com/staude/amiscara-agents)), gebaut auf [russh](https://github.com/Eugeny/russh).

Ins Crate gehört alles, was nur SSH ist: Verbindungsaufbau und Anmeldung, Host-Key-Prüfung mit TOFU, Schlüssel, Kanäle für Shell mit PTY, `direct-tcpip` und `direct-streamlocal`. SFTP und Jump-Ketten folgen. Was zu einer App gehört, bleibt in der App.

## Einbinden

Die Apps binden das Crate als Git-Abhängigkeit mit festem Tag ein:

```toml
amiscara-ssh = { git = "https://github.com/staude/amiscara-ssh", tag = "v0.1.0" }
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
};
let session = Session::connect(&target).await?;
let mut shell = session.open_shell("xterm-256color", PtySize { cols: 80, rows: 24 }).await?;
shell.write(b"uptime\n").await?;
while let Some(ShellEvent::Output(bytes)) = shell.next().await {
    print!("{}", String::from_utf8_lossy(&bytes));
}
```

## Release

SemVer ab `0.1.0`. Solange 0.x gilt, bricht eine neue Minor-Version die Schnittstelle. Ablauf: PR mit Eintrag in `CHANGELOG.md`, Squash-Merge, `[Unreleased]` zur neuen Version machen, Tag `v<version>` pushen.

## Lizenz

MIT oder Apache-2.0, nach Wahl: [LICENSE-MIT](LICENSE-MIT), [LICENSE-APACHE](LICENSE-APACHE).
