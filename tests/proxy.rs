//! ProxyCommand without a server: a command that ends before the sign-in.
//! Runs everywhere, no container needed.

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
