//! Tests against the local SSH container. Start it first:
//!
//! ```sh
//! scripts/ssh-testserver.sh start
//! cargo test -- --ignored
//! scripts/ssh-testserver.sh stop
//! ```

use std::path::PathBuf;
use std::time::Duration;

use amiscara_ssh::{
    HostKeyPolicy, Identity, PtySize, Session, Shell, ShellEvent, SshError, SshTarget, Zeroizing,
    keys,
};
use tokio::io::AsyncWriteExt;

const HOST: &str = "127.0.0.1";
const USER: &str = "tester";
const PASSWORD: &str = "tester-pw";

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn port() -> u16 {
    std::env::var("AMISCARA_SSH_TEST_PORT")
        .ok()
        .and_then(|port| port.parse().ok())
        .unwrap_or(2222)
}

fn key_file() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/ssh-testserver/id_ed25519")
}

fn target(identity: Identity, host_key: HostKeyPolicy) -> SshTarget {
    SshTarget {
        host: HOST.into(),
        port: port(),
        user: USER.into(),
        identity,
        host_key,
        agent_forward: false,
    }
}

fn key_identity() -> Identity {
    Identity::File {
        path: key_file(),
        passphrase: None,
    }
}

fn password(password: &str) -> Identity {
    Identity::Password(Zeroizing::new(password.into()))
}

/// Trust on first use in a fresh `known_hosts`.
fn tofu(dir: &tempfile::TempDir) -> HostKeyPolicy {
    HostKeyPolicy::KnownHostsFile {
        path: dir.path().join("known_hosts"),
        accept_new: true,
    }
}

#[tokio::test]
#[ignore = "braucht scripts/ssh-testserver.sh start"]
async fn signs_in_with_key() -> TestResult {
    let dir = tempfile::tempdir()?;
    let session = Session::connect(&target(key_identity(), tofu(&dir))).await?;
    session.disconnect().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "braucht scripts/ssh-testserver.sh start"]
async fn signs_in_with_password() -> TestResult {
    let dir = tempfile::tempdir()?;
    let session = Session::connect(&target(password(PASSWORD), tofu(&dir))).await?;
    session.disconnect().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "braucht scripts/ssh-testserver.sh start"]
async fn wrong_password_fails() -> TestResult {
    let dir = tempfile::tempdir()?;
    match Session::connect(&target(password("falsch"), tofu(&dir))).await {
        Err(SshError::AuthFailed(who)) => {
            assert_eq!(who, format!("{USER}@{HOST}"));
            assert!(!who.contains("falsch"));
        }
        Err(other) => return Err(format!("expected AuthFailed, got {other}").into()),
        Ok(_) => return Err("signed in with a wrong password".into()),
    }
    Ok(())
}

#[tokio::test]
#[ignore = "braucht scripts/ssh-testserver.sh start"]
async fn trust_on_first_use_records_the_key() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("known_hosts");
    Session::connect(&target(key_identity(), tofu(&dir)))
        .await?
        .disconnect()
        .await?;
    let recorded = std::fs::read_to_string(&path)?;
    let host_port = format!("[{HOST}]:{} ", port());
    assert!(
        recorded.lines().any(|line| line.starts_with(&host_port)),
        "{recorded}"
    );

    let strict = HostKeyPolicy::KnownHostsFile {
        path,
        accept_new: false,
    };
    Session::connect(&target(key_identity(), strict))
        .await?
        .disconnect()
        .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "braucht scripts/ssh-testserver.sh start"]
async fn unknown_host_key_is_refused_without_accept_new() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("known_hosts");
    std::fs::write(&path, "")?;
    let strict = HostKeyPolicy::KnownHostsFile {
        path,
        accept_new: false,
    };
    match Session::connect(&target(key_identity(), strict)).await {
        Err(SshError::UnknownHostKey { fingerprint, .. }) => {
            assert!(fingerprint.starts_with("SHA256:"));
        }
        Err(other) => return Err(format!("expected UnknownHostKey, got {other}").into()),
        Ok(_) => return Err("connected to an unknown host".into()),
    }
    Ok(())
}

#[tokio::test]
#[ignore = "braucht scripts/ssh-testserver.sh start"]
async fn other_pinned_key_is_a_changed_key() -> TestResult {
    let other = keys::generate_ed25519("")?;
    let pinned = HostKeyPolicy::Pinned(Some(other.public_openssh));
    match Session::connect(&target(key_identity(), pinned)).await {
        Err(SshError::HostKeyChanged { .. }) => {}
        Err(other) => return Err(format!("expected HostKeyChanged, got {other}").into()),
        Ok(_) => return Err("connected despite a different pinned key".into()),
    }
    Ok(())
}

/// Reads output until a line consists of exactly `rows cols`. The echo of
/// the command and the prompt do not match.
async fn wait_for_size(shell: &mut Shell, rows: u16, cols: u16) -> TestResult {
    let wanted = format!("{rows} {cols}");
    let mut output = Vec::new();
    let read = async {
        while let Some(event) = shell.next().await {
            match event {
                ShellEvent::Output(bytes) => output.extend_from_slice(&bytes),
                ShellEvent::Exit(status) => return Err(format!("shell exited with {status}")),
                ShellEvent::Signal(signal) => return Err(format!("shell ended by {signal}")),
            }
            let text = String::from_utf8_lossy(&output);
            if text.lines().any(|line| line.trim() == wanted) {
                return Ok(());
            }
        }
        Err("shell closed".to_owned())
    };
    match tokio::time::timeout(Duration::from_secs(10), read).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => Err(err.into()),
        Err(_) => Err(format!(
            "no line `{wanted}` within 10 s, got: {}",
            String::from_utf8_lossy(&output)
        )
        .into()),
    }
}

#[tokio::test]
#[ignore = "braucht scripts/ssh-testserver.sh start"]
async fn shell_has_pty_size_and_follows_resize() -> TestResult {
    let dir = tempfile::tempdir()?;
    let session = Session::connect(&target(key_identity(), tofu(&dir))).await?;
    let mut shell = session
        .open_shell("xterm-256color", PtySize { cols: 80, rows: 24 })
        .await?;
    shell.write(b"stty size\n").await?;
    wait_for_size(&mut shell, 24, 80).await?;

    shell
        .resize(PtySize {
            cols: 100,
            rows: 30,
        })
        .await?;
    shell.write(b"stty size\n").await?;
    wait_for_size(&mut shell, 30, 100).await?;

    shell.write(b"exit 3\n").await?;
    let exit = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(event) = shell.next().await {
            if let ShellEvent::Exit(status) = event {
                return Some(status);
            }
        }
        None
    })
    .await?;
    assert_eq!(exit, Some(3));
    session.disconnect().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "braucht scripts/ssh-testserver.sh start"]
async fn shell_killed_by_signal_reports_it() -> TestResult {
    let dir = tempfile::tempdir()?;
    let session = Session::connect(&target(key_identity(), tofu(&dir))).await?;
    let mut shell = session
        .open_shell("xterm-256color", PtySize { cols: 80, rows: 24 })
        .await?;
    shell.write(b"kill -9 $$\n").await?;
    let signal = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(event) = shell.next().await {
            if let ShellEvent::Signal(signal) = event {
                return Some(signal);
            }
        }
        None
    })
    .await?;
    assert_eq!(signal.as_deref(), Some("KILL"));
    session.disconnect().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "braucht scripts/ssh-testserver.sh start"]
async fn sftp_creates_writes_reads_renames_and_removes() -> TestResult {
    let dir = tempfile::tempdir()?;
    let session = Session::connect(&target(key_identity(), tofu(&dir))).await?;
    let sftp = session.open_sftp().await?;
    let home = sftp.canonicalize(".").await?;
    let base = format!("{home}/sftp-test-{}", std::process::id());
    sftp.create_dir(base.as_str()).await?;

    let first = format!("{base}/eins.txt");
    let second = format!("{base}/zwei.txt");
    // `write` needs an existing file, `create` makes it.
    let mut file = sftp.create(first.as_str()).await?;
    file.write_all(b"hallo sftp").await?;
    file.shutdown().await?;
    assert_eq!(sftp.read(first.as_str()).await?, b"hallo sftp");
    let names: Vec<String> = sftp
        .read_dir(base.as_str())
        .await?
        .map(|entry| entry.file_name())
        .collect();
    assert_eq!(names, vec!["eins.txt".to_owned()]);

    sftp.rename(first.as_str(), second.as_str()).await?;
    assert!(!sftp.try_exists(first.as_str()).await?);
    assert_eq!(sftp.metadata(second.as_str()).await?.len(), 10);

    sftp.remove_file(second.as_str()).await?;
    sftp.remove_dir(base.as_str()).await?;
    assert!(!sftp.try_exists(base.as_str()).await?);
    sftp.close().await?;
    session.disconnect().await?;
    Ok(())
}
