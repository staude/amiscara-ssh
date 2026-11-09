//! ProxyCommand without a server: a command that ends before the sign-in.
//! Runs everywhere, no container needed.

use std::time::Duration;

use amiscara_ssh::{HostKeyPolicy, Identity, Session, SshError, SshTarget};

fn target() -> SshTarget {
    SshTarget {
        host: "127.0.0.1".into(),
        port: 22,
        user: "tester".into(),
        identity: Identity::Agent,
        host_key: HostKeyPolicy::Pinned(None),
        agent_forward: false,
        keyboard_interactive: None,
    }
}

#[cfg(unix)]
// The shell runs `exec <command>`, as OpenSSH does, so a list needs a shell
// of its own.
const FAILING: &str = "sh -c 'echo kaputt >&2; exit 3'";
#[cfg(windows)]
const FAILING: &str = "echo kaputt 1>&2 & exit /b 3";

#[tokio::test]
async fn ending_command_names_status_and_error_output() {
    match Session::connect_command(FAILING, &target()).await {
        Err(SshError::ProxyCommand(reason)) => {
            assert!(reason.contains('3'), "{reason}");
            assert!(reason.contains("kaputt"), "{reason}");
            assert!(!reason.contains("echo"), "names the command: {reason}");
        }
        Err(other) => panic!("expected ProxyCommand, got {other:?}"),
        Ok(_) => panic!("signed in over a command that ended"),
    }
}

#[tokio::test]
async fn unknown_placeholder_starts_nothing() {
    match Session::connect_command("nc %h %q", &target()).await {
        Err(SshError::ProxyCommand(reason)) => assert!(reason.contains("%q"), "{reason}"),
        Err(other) => panic!("expected ProxyCommand, got {other:?}"),
        Ok(_) => panic!("signed in over an unknown placeholder"),
    }
}

#[cfg(unix)]
#[tokio::test]
async fn error_output_never_names_the_command() {
    // bash repeats the whole line on a syntax error, dash does not.
    let command = "helper --token geheim-1234567890abcdef (";
    match Session::connect_command(command, &target()).await {
        Err(SshError::ProxyCommand(reason)) => {
            assert!(!reason.contains("geheim"), "{reason}");
        }
        Err(other) => panic!("expected ProxyCommand, got {other:?}"),
        Ok(_) => panic!("signed in over a broken command"),
    }
}

#[cfg(unix)]
#[tokio::test]
async fn error_written_after_closing_stdout_still_counts() {
    let command = "sh -c 'exec 1>&-; sleep 0.3; echo kaputt >&2; exit 3'";
    match Session::connect_command(command, &target()).await {
        Err(SshError::ProxyCommand(reason)) => {
            assert!(
                reason.contains('3') && reason.contains("kaputt"),
                "{reason}"
            );
        }
        Err(other) => panic!("expected ProxyCommand, got {other:?}"),
        Ok(_) => panic!("signed in over a command that ended"),
    }
}

#[cfg(unix)]
#[tokio::test]
async fn ended_command_does_not_wait_for_what_it_started() {
    // The background sleep keeps stdout open after the command ended.
    let command = "sh -c 'sleep 30 2>/dev/null & echo kaputt >&2; exit 3'";
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        Session::connect_command(command, &target()),
    )
    .await;
    match result {
        Ok(Err(SshError::ProxyCommand(reason))) => assert!(reason.contains("kaputt"), "{reason}"),
        Ok(Err(other)) => panic!("expected ProxyCommand, got {other:?}"),
        Ok(Ok(_)) => panic!("signed in over a command that ended"),
        Err(_) => panic!("still waiting 5 s after the command ended"),
    }
}

/// A command that never answers; the test drops `connect_command` after a
/// second, which drops the transport.
async fn connect_and_give_up(command: &str) {
    let gave_up = tokio::time::timeout(
        Duration::from_secs(1),
        Session::connect_command(command, &target()),
    )
    .await;
    if let Ok(result) = gave_up {
        panic!("the command answered: {:?}", result.err());
    }
}

#[cfg(unix)]
#[tokio::test]
async fn dropped_transport_ends_the_command() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let pid_file = dir.path().join("pid");
    connect_and_give_up(&format!(
        "sh -c 'echo $$ > {}; exec sleep 30'",
        pid_file.display()
    ))
    .await;
    let pid = std::fs::read_to_string(&pid_file)?.trim().to_owned();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        let alive = std::process::Command::new("kill")
            .args(["-0", &pid])
            .stderr(std::process::Stdio::null())
            .status()?
            .success();
        if !alive {
            return Ok(());
        }
        if tokio::time::Instant::now() > deadline {
            return Err(format!("command {pid} still runs 3 s after the drop").into());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// On Windows `cmd.exe` runs the command below it; the drop has to end that
/// too. The inner loop appends to a file every second while it lives.
#[cfg(windows)]
#[tokio::test]
async fn dropped_transport_ends_the_command_below_cmd() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let file = dir.path().join("ticks");
    connect_and_give_up(&format!(
        "cmd /C \"for /L %%i in (1,1,60) do (echo x>>{} & ping -n 2 127.0.0.1 >nul)\"",
        file.display()
    ))
    .await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let before = std::fs::metadata(&file)?.len();
    tokio::time::sleep(Duration::from_secs(3)).await;
    let after = std::fs::metadata(&file)?.len();
    assert!(before > 0, "the command never ran");
    assert_eq!(before, after, "the command below cmd.exe still runs");
    Ok(())
}

/// A helper that ends with success once its stdin closes, behind a server
/// that sends garbage: the error is the one of SSH, not of the command.
#[cfg(unix)]
#[tokio::test]
async fn protocol_error_is_not_blamed_on_a_helper_that_follows() {
    let command = r#"sh -c 'printf "SSH-2.0-x\r\nGARBAGEGARBAGEGARBAGE\n"; cat >/dev/null'"#;
    match Session::connect_command(command, &target()).await {
        Err(SshError::ProxyCommand(reason)) => panic!("blamed the command: {reason}"),
        Err(_) => {}
        Ok(_) => panic!("signed in over garbage"),
    }
}
