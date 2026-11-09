# amiscara-ssh

Gemeinsamer SSH-Client der Amiscara-Apps ([Amiscara Connect](https://github.com/staude/amiscara-connect) und [Amiscara Agents](https://github.com/staude/amiscara-agents)), gebaut auf [russh](https://github.com/Eugeny/russh).

Ins Crate gehört alles, was nur SSH ist: Verbindungsaufbau und Anmeldung, Host-Key-Prüfung mit TOFU, Schlüssel, Kanäle für Shell mit PTY, `direct-tcpip` und `direct-streamlocal`, Jump-Host-Ketten mit Sitzungs-Pool und Agent-Forwarding, Einmalcodes per keyboard-interactive, SFTP über `Session::open_sftp`. Was zu einer App gehört, bleibt in der App.

## Einbinden

Die Apps binden das Crate als Git-Abhängigkeit mit festem Tag ein:

```toml
amiscara-ssh = { git = "https://github.com/staude/amiscara-ssh", tag = "v0.5.0" }
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
- Tests gegen die Jump-Host-Kette (braucht Docker): `scripts/ssh-testkette.sh run` startet Bastion, Jump und Ziel als Container, einen eigenen `ssh-agent` mit dem Testschlüssel, führt `cargo test --test chain -- --ignored` aus und baut alles wieder ab, auch bei Fehlern. Von außen erreichbar sind nur die Bastionen, die Bastion mit Passwort auf `127.0.0.1:2223` (anderer Port über `AMISCARA_SSH_CHAIN_PORT`); jeder Sprung hat eigenen Benutzer, eigene Zugangsdaten und eigenen Host-Key, alles in `target/ssh-testkette/`. Daneben läuft `otp-bastion` auf `127.0.0.1:2224` (anderer Port über `AMISCARA_SSH_OTP_PORT`), eine Bastion, die nach dem Schlüssel `id_otp` per keyboard-interactive einen TOTP-Code verlangt (Geheimnis in `target/ssh-testkette/totp_secret`); dahinter dieselben Jump und Ziel. `start` und `stop` gibt es auch einzeln.

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
    keyboard_interactive: None,
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
let route = Route { jumps: vec![bastion, jump], target, proxy_command: None };
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
- Der Pool-Schlüssel ist der Weg aus Host, Port und Benutzer je Sprung (beim Ziel auch `agent_forward`, beim ersten Sprung auch `proxy_command`). Zugangsdaten und Host-Key-Regel gehören nicht dazu: Eine lebende Verbindung wird so weiterbenutzt, wie sie angemeldet und geprüft wurde.

## Einmalcodes

Will ein Server bei der Anmeldung etwas wissen, etwa eine Bastion nach dem Schlüssel einen Einmalcode, fragt das Crate per keyboard-interactive die App: `SshTarget::keyboard_interactive` nimmt ein `Arc<dyn KeyboardInteractive>`. Gefragt wird nur der Sprung, der fragt, und nur wenn der Server die `Identity` als Teilerfolg angenommen hat und danach noch keyboard-interactive verlangt. Abgelehnte Schlüssel oder Passwörter bleiben eine Ablehnung (`SshError::AuthFailed`), ohne Frage; ein Server, der nur keyboard-interactive anbietet, wird nicht unterstützt.

```rust
use std::sync::Arc;
use amiscara_ssh::{KeyboardAnswer, KeyboardInteractive, KeyboardPrompt, PromptFuture, Zeroizing};

#[derive(Debug)]
struct Dialog; // in der App: Rückfrage an die Oberfläche

impl KeyboardInteractive for Dialog {
    fn ask(&self, prompt: KeyboardPrompt) -> PromptFuture {
        // prompt.route[prompt.index] ist der fragende Sprung, prompt.route der Weg,
        // prompt.prompts die Fragen (echo false: verdeckt eingeben), prompt.attempt ab 1
        Box::pin(async move {
            let code = String::from("123456"); // vom Nutzer
            Some(KeyboardAnswer {
                responses: vec![Zeroizing::new(code)],
                keep_open: None, // Häkchen "offen halten": Some(Duration::from_secs(600))
            })
        })
    }
}

// bastion ist ein SshTarget wie oben
bastion.keyboard_interactive = Some(Arc::new(Dialog));
```

- Während der Frage meldet der Sprung `HopState::AwaitingInput`. Die Wartezeit zählt nicht zu `PoolConfig::connect_timeout` und nicht zur Latenz.
- `None` als Antwort bricht ab: `SshError::Cancelled`, im Ereignis `HopFailure::Cancelled`. Vom fragenden Sprung bleibt nichts im Pool, auch nicht bei einem fallengelassenen `connect` während der Frage; ein Sprung davor, der schon einen Code bekommen hat, bleibt wie nach der letzten `Lease` offen.
- Ein abgelehnter Code wird auf derselben Verbindung neu erfragt, höchstens drei Versuche (`attempt` 1 bis 3), danach `SshError::AuthFailed`. Verlangt der Server mehrere Schritte per keyboard-interactive nacheinander, bleibt `attempt` beim nächsten Schritt gleich. Mehr als 16 Anfragen und Schritte in einer Anmeldung lehnt das Crate ab (`SshError::AuthFailed`).
- Die Wartezeit begrenzt der Server selbst (OpenSSH `LoginGraceTime`, meist 120 s); antwortet der Nutzer später, endet der Aufbau mit `HopFailure::Closed`.
- Der Pool hält einen Sprung, der gefragt hat, nach der letzten `Lease` noch offen: `keep_open` der Antwort, sonst `PoolConfig::code_grace` (60 s). In dieser Zeit braucht eine neue Sitzung keinen Code, auch nicht nach einem Fehler weiter hinten, etwa einer Host-Key-Bestätigung. `SessionPool::close_idle` schließt alle ungenutzten Verbindungen sofort, etwa beim Sperren der App. Schließt die Bastion ungenutzte Verbindungen selbst (OpenSSH `UnusedConnectionTimeout`), endet das Offenhalten früher. Offengehalten wird nur, wenn die letzte `Lease` in einer Tokio-Runtime fallengelassen wird; außerhalb davon (etwa auf einem fremden Thread) schließt der Sprung sofort.
- russh kopiert die Antworten beim Senden in einfache `String`s; nur die Kopien in `KeyboardAnswer` werden beim Drop gelöscht.

## ProxyCommand

Manche Server erreicht man nur über ein Hilfsprogramm, etwa `cloudflared` oder AWS SSM. `Session::connect_command` startet einen lokalen Befehl und spricht SSH über dessen stdin und stdout; in einer Kette übernimmt `Route::proxy_command` das für den ersten Sprung (den ersten Jump oder, ohne Jumps, das Ziel).

```rust
use amiscara_ssh::{Route, Session};

// target ist ein SshTarget wie oben
let session = Session::connect_command("cloudflared access ssh --hostname %h", &target).await?;

let route = Route {
    proxy_command: Some("aws ssm start-session --target %h --document-name AWS-StartSSHSession --parameters portNumber=%p".into()),
    ..Route::direct(target)
};
let session = pool.connect(&route).await?;
```

- Platzhalter wie in OpenSSH: `%h` Host, `%p` Port, `%r` Benutzer, `%%` ein `%`. Ein anderer Platzhalter oder ein einzelnes `%` am Ende endet vor dem Start in `SshError::ProxyCommand`.
- Host und Benutzer kommen ungeschützt in die Befehlszeile. Sie dürfen deshalb nur aus ASCII-Buchstaben, Ziffern und `. - _ : @` bestehen und nicht mit `-` beginnen, sonst lehnt das Crate vor dem Start ab. So kann ein Eintrag in einem geteilten Dokument keine fremden Befehle einschleusen.
- Der Befehl läuft auf Unix als `/bin/sh -c "exec <Befehl>"` (wie OpenSSH), auf Windows als `cmd.exe /S /C "<Befehl>"` ohne Konsolenfenster, Anführungszeichen im Befehl (etwa um `C:\Program Files\…`) bleiben erhalten.
- Endet der Befehl vor der Anmeldung, nennt `SshError::ProxyCommand` seinen Exit-Status und die letzten 2 KiB seiner Fehlerausgabe, nie den Befehl selbst (er kann ein Zugangs-Token enthalten): Wiederholt die Fehlerausgabe ihn, etwa die Shell bei einem Syntaxfehler, steht dort `<command>`, Wörter des Befehls ab 16 Zeichen werden zu `…`. Das gilt auch, wenn der Befehl endet, während ein von ihm gestarteter Prozess stdout noch offen hält. Im Ereignis steht `HopFailure::ProxyCommand`. Host-Key- und Anmeldefehler bleiben, was sie sind. Auch `Debug` von `Route` zeigt den Befehl nicht.
- Im Pool darf der Aufbau des ersten Sprungs über einen Befehl bis zu `PoolConfig::proxy_connect_timeout` dauern (120 s), weil etwa `cloudflared` beim ersten Mal auf die Anmeldung im Browser wartet. `Session::connect_command` hat wie `Session::connect` kein eigenes Zeitlimit.
- Endet die Verbindung, beendet das Crate den Befehl; endet er nicht binnen einer Sekunde von selbst, wird er abgeschossen, auf Windows samt allem, was unter `cmd.exe` läuft.

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
