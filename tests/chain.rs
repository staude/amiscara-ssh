//! Tests against the local jump host chain (bastion -> jump -> target). Run
//! them with the chain and an agent of their own:
//!
//! ```sh
//! scripts/ssh-testkette.sh run
//! ```
//!
//! Index 0 is the bastion, 1 the jump, 2 the target. The tests stop and start
//! the jump container, so they run one at a time (`--test-threads=1`).

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use amiscara_ssh::{
    HopEvent, HopFailure, HopState, HostKeyPolicy, Identity, PoolConfig, PtySize, Route, Session,
    SessionPool, ShellEvent, SshError, SshTarget, Zeroizing, keys,
};
use tokio::sync::broadcast;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn state() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/ssh-testkette")
}

fn port() -> u16 {
    std::env::var("AMISCARA_SSH_CHAIN_PORT")
        .ok()
        .and_then(|port| port.parse().ok())
        .unwrap_or(2223)
}

fn strict() -> HostKeyPolicy {
    HostKeyPolicy::KnownHostsFile {
        path: state().join("known_hosts"),
        accept_new: false,
    }
}

fn bastion() -> SshTarget {
    SshTarget {
        host: "127.0.0.1".into(),
        port: port(),
        user: "bastion-user".into(),
        identity: Identity::Password(Zeroizing::new("bastion-pw".into())),
        host_key: strict(),
        agent_forward: false,
    }
}

fn jump() -> SshTarget {
    SshTarget {
        host: "jump".into(),
        port: 22,
        user: "jump-user".into(),
        identity: Identity::File {
            path: state().join("id_jump"),
            passphrase: None,
        },
        host_key: strict(),
        agent_forward: false,
    }
}

fn target() -> SshTarget {
    SshTarget {
        host: "target".into(),
        port: 22,
        user: "target-user".into(),
        identity: Identity::Agent,
        host_key: strict(),
        agent_forward: false,
    }
}

fn chain() -> Route {
    Route {
        jumps: vec![bastion(), jump()],
        target: target(),
    }
}

/// Everything already sent, for example by a finished `connect`.
fn drain(events: &mut broadcast::Receiver<HopEvent>) -> Vec<(usize, HopState)> {
    let mut seen = Vec::new();
    while let Ok(event) = events.try_recv() {
        seen.push((event.index, event.state));
    }
    seen
}

/// Waits until every hop in `indices` reported `Closed`; returns all events
/// seen meanwhile.
async fn wait_closed(
    events: &mut broadcast::Receiver<HopEvent>,
    indices: &[usize],
    limit: Duration,
) -> Result<Vec<(usize, HopState)>, String> {
    let mut seen = Vec::new();
    let mut missing: BTreeSet<usize> = indices.iter().copied().collect();
    let wait = async {
        while !missing.is_empty() {
            match events.recv().await {
                Ok(event) => {
                    if event.state == HopState::Closed {
                        missing.remove(&event.index);
                    }
                    seen.push((event.index, event.state));
                }
                Err(err) => return Err(err.to_string()),
            }
        }
        Ok(())
    };
    match tokio::time::timeout(limit, wait).await {
        Ok(Ok(())) => Ok(seen),
        Ok(Err(err)) => Err(err),
        Err(_) => Err(format!(
            "no Closed for {missing:?} within {limit:?}, saw {seen:?}"
        )),
    }
}

fn states_of(seen: &[(usize, HopState)], index: usize) -> Vec<&HopState> {
    seen.iter()
        .filter(|(i, _)| *i == index)
        .map(|(_, state)| state)
        .collect()
}

fn connected(state: &HopState) -> bool {
    matches!(state, HopState::Connected { .. })
}

/// Runs `command` in a new shell and waits for a line that is exactly
/// `wanted`. The echo of the command and the prompt do not match.
async fn shell_line(session: &Session, command: &str, wanted: &str) -> TestResult {
    let mut shell = session
        .open_shell(
            "xterm-256color",
            PtySize {
                cols: 200,
                rows: 24,
            },
        )
        .await?;
    shell.write(format!("{command}\n").as_bytes()).await?;
    let mut output = Vec::new();
    let read = async {
        while let Some(event) = shell.next().await {
            if let ShellEvent::Output(bytes) = event {
                output.extend_from_slice(&bytes);
            }
            if String::from_utf8_lossy(&output)
                .lines()
                .any(|line| line.trim() == wanted)
            {
                return true;
            }
        }
        false
    };
    let found = tokio::time::timeout(Duration::from_secs(10), read).await;
    shell.close().await.ok();
    match found {
        Ok(true) => Ok(()),
        _ => Err(format!(
            "no line `{wanted}` after `{command}`, got: {}",
            String::from_utf8_lossy(&output)
        )
        .into()),
    }
}

fn compose(args: &[&str]) -> TestResult {
    let file = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/kette/compose.yml");
    let out = Command::new("docker")
        .arg("compose")
        .arg("-f")
        .arg(file)
        .args(args)
        .output()?;
    if !out.status.success() {
        return Err(format!(
            "docker compose {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    Ok(())
}

#[tokio::test]
#[ignore = "braucht scripts/ssh-testkette.sh run"]
async fn shell_on_target_over_two_jumps() -> TestResult {
    let pool = SessionPool::new(PoolConfig::default());
    let mut events = pool.subscribe();
    let lease = pool.connect(&chain()).await?;
    let seen = drain(&mut events);
    for index in 0..3 {
        let states = states_of(&seen, index);
        assert_eq!(states.first(), Some(&&HopState::Connecting), "{seen:?}");
        assert!(states.get(1).is_some_and(|s| connected(s)), "{seen:?}");
    }
    let route = chain().labels();
    assert_eq!(route[1], "jump-user@jump:22");
    shell_line(&lease, "hostname", "target").await?;
    Ok(())
}

#[tokio::test]
#[ignore = "braucht scripts/ssh-testkette.sh run"]
async fn second_lease_reuses_every_hop_and_last_drop_closes_all() -> TestResult {
    let pool = SessionPool::new(PoolConfig::default());
    let mut events = pool.subscribe();
    let first = pool.connect(&chain()).await?;
    drain(&mut events);

    let second = pool.connect(&chain()).await?;
    let seen = drain(&mut events);
    assert_eq!(
        seen,
        vec![
            (0, HopState::Reused),
            (1, HopState::Reused),
            (2, HopState::Reused)
        ]
    );
    shell_line(&second, "hostname", "target").await?;

    drop(first);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(drain(&mut events).is_empty(), "closed while still leased");
    assert!(!second.is_closed());

    drop(second);
    let seen = wait_closed(&mut events, &[0, 1, 2], Duration::from_secs(10)).await?;
    for index in 0..3 {
        assert_eq!(states_of(&seen, index), vec![&HopState::Closed], "{seen:?}");
    }
    Ok(())
}

#[tokio::test]
#[ignore = "braucht scripts/ssh-testkette.sh run"]
async fn fresh_session_connects_only_the_target() -> TestResult {
    let pool = SessionPool::new(PoolConfig::default());
    let mut events = pool.subscribe();
    let shared = pool.connect(&chain()).await?;
    drain(&mut events);

    let fresh = pool.connect_fresh(&chain()).await?;
    let seen = drain(&mut events);
    assert_eq!(states_of(&seen, 0), vec![&HopState::Reused], "{seen:?}");
    assert_eq!(states_of(&seen, 1), vec![&HopState::Reused], "{seen:?}");
    let target = states_of(&seen, 2);
    assert_eq!(target.first(), Some(&&HopState::Connecting), "{seen:?}");
    assert!(target.get(1).is_some_and(|s| connected(s)), "{seen:?}");
    shell_line(&fresh, "hostname", "target").await?;

    drop(fresh);
    let seen = wait_closed(&mut events, &[2], Duration::from_secs(10)).await?;
    assert_eq!(seen, vec![(2, HopState::Closed)]);
    assert!(!shared.is_closed(), "the shared target stays open");
    shell_line(&shared, "hostname", "target").await?;
    Ok(())
}

#[tokio::test]
#[ignore = "braucht scripts/ssh-testkette.sh run"]
async fn wrong_host_key_names_the_middle_hop() -> TestResult {
    let pool = SessionPool::new(PoolConfig::default());
    let mut events = pool.subscribe();
    let mut route = chain();
    route.jumps[1].host_key =
        HostKeyPolicy::Pinned(Some(keys::generate_ed25519("")?.public_openssh));
    match pool.connect(&route).await {
        Err(SshError::Hop { index, hop, source }) => {
            assert_eq!(index, 1);
            assert_eq!(hop, "jump-user@jump:22");
            assert!(
                matches!(*source, SshError::HostKeyChanged { ref host, .. } if host == "jump"),
                "{source}"
            );
        }
        Err(other) => return Err(format!("expected Hop 1, got {other}").into()),
        Ok(_) => return Err("connected despite a wrong host key".into()),
    }
    let seen = drain(&mut events);
    assert!(
        seen.contains(&(1, HopState::Failed(HopFailure::HostKeyChanged))),
        "{seen:?}"
    );
    assert!(states_of(&seen, 2).is_empty(), "{seen:?}");
    // Nothing half built stays: the bastion built for this call is closed.
    wait_closed(&mut events, &[0], Duration::from_secs(10)).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "braucht scripts/ssh-testkette.sh run"]
async fn unresolvable_target_is_a_refused_channel() -> TestResult {
    let pool = SessionPool::new(PoolConfig::default());
    let mut events = pool.subscribe();
    let mut route = chain();
    route.target.host = "nirgendwo.invalid".into();
    match pool.connect(&route).await {
        Err(err @ SshError::Hop { index: 2, .. }) => {
            assert_eq!(HopFailure::from(&err), HopFailure::ChannelRefused, "{err}");
        }
        Err(other) => return Err(format!("expected Hop 2, got {other}").into()),
        Ok(_) => return Err("connected to an unresolvable target".into()),
    }
    let seen = drain(&mut events);
    assert!(
        seen.contains(&(2, HopState::Failed(HopFailure::ChannelRefused))),
        "{seen:?}"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "braucht scripts/ssh-testkette.sh run"]
async fn agent_reaches_only_the_target_and_only_when_on() -> TestResult {
    let pool = SessionPool::new(PoolConfig::default());
    let has_socket = r#"test -n "$SSH_AUTH_SOCK"; echo "sock=$?""#;

    // Off: neither the target nor the jump sees an agent.
    let off = pool.connect(&chain()).await?;
    shell_line(&off, has_socket, "sock=1").await?;

    // On: the target can list the keys of the agent ...
    let mut route = chain();
    route.target.agent_forward = true;
    route.jumps[1].agent_forward = true; // ignored for jumps
    let on = pool.connect(&route).await?;
    assert!(on.agent_forward());
    shell_line(&on, "ssh-add -l >/dev/null; echo \"agent=$?\"", "agent=0").await?;

    // ... while the jump, the same pooled connection, still sees none.
    let mut events = pool.subscribe();
    let to_jump = Route {
        jumps: vec![bastion()],
        target: jump(),
    };
    let jump = pool.connect(&to_jump).await?;
    assert_eq!(
        drain(&mut events),
        vec![(0, HopState::Reused), (1, HopState::Reused)]
    );
    assert!(!jump.agent_forward());
    shell_line(&jump, has_socket, "sock=1").await?;
    shell_line(&off, has_socket, "sock=1").await?;
    Ok(())
}

#[tokio::test]
#[ignore = "braucht scripts/ssh-testkette.sh run"]
async fn killed_jump_closes_behind_it_and_is_rebuilt_from_there() -> TestResult {
    let pool = SessionPool::new(PoolConfig::default());
    let mut events = pool.subscribe();
    let old = pool.connect(&chain()).await?;
    drain(&mut events);

    compose(&["kill", "jump"])?;
    let closed = wait_closed(&mut events, &[1, 2], Duration::from_secs(30)).await;
    // Start again before checking, so a failure here does not break the
    // tests after it.
    compose(&["start", "jump"])?;
    let closed = closed?;
    assert!(states_of(&closed, 0).is_empty(), "{closed:?}");
    assert!(old.is_closed());

    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let new = loop {
        drain(&mut events);
        match pool.connect(&chain()).await {
            Ok(lease) => break lease,
            Err(err) if tokio::time::Instant::now() < deadline => {
                eprintln!("jump noch nicht bereit: {err}");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(err) => return Err(err.into()),
        }
    };
    let seen = drain(&mut events);
    assert_eq!(states_of(&seen, 0), vec![&HopState::Reused], "{seen:?}");
    for index in [1, 2] {
        let states = states_of(&seen, index);
        assert_eq!(states.first(), Some(&&HopState::Connecting), "{seen:?}");
        assert!(states.get(1).is_some_and(|s| connected(s)), "{seen:?}");
    }

    // The lease on the dead connection must not take the new one with it.
    drop(old);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!new.is_closed());
    shell_line(&new, "hostname", "target").await?;
    Ok(())
}

#[tokio::test]
#[ignore = "braucht scripts/ssh-testkette.sh run"]
async fn cancelled_connect_leaves_nothing_open() -> TestResult {
    let pool = SessionPool::new(PoolConfig::default());
    let mut events = pool.subscribe();
    let task = tokio::spawn({
        let pool = pool.clone();
        async move { pool.connect(&chain()).await.map(drop) }
    });
    // Cancel once the bastion is in the pool, while the rest still builds.
    let bastion_up = tokio::time::timeout(Duration::from_secs(10), async {
        while let Ok(event) = events.recv().await {
            if event.index == 0 && connected(&event.state) {
                return true;
            }
        }
        false
    })
    .await;
    task.abort();
    if !matches!(bastion_up, Ok(true)) {
        return Err("bastion never connected".into());
    }
    wait_closed(&mut events, &[0], Duration::from_secs(10)).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "braucht scripts/ssh-testkette.sh run"]
async fn agent_channel_is_refused_when_off() -> TestResult {
    use amiscara_ssh::ChannelMsg;
    let pool = SessionPool::new(PoolConfig::default());
    let off = pool.connect(&chain()).await?;
    assert!(!off.agent_forward());
    // Ask for forwarding behind the back of the session: the server then
    // opens agent channels, and the client must refuse them.
    let mut channel = off.channel_session().await?;
    channel.agent_forward(true).await?;
    channel.request_shell(true).await?;
    channel
        .data(&b"ssh-add -l >/dev/null 2>&1; echo \"agent=$?\"; exit\n"[..])
        .await?;
    let mut output = Vec::new();
    let read = async {
        while let Some(msg) = channel.wait().await {
            if let ChannelMsg::Data { data } = msg {
                output.extend_from_slice(&data);
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(10), read).await?;
    let text = String::from_utf8_lossy(&output);
    // sshd's socket is there, but the refused channel yields no keys (1);
    // an accepted one would list the key in the local agent (0).
    assert!(text.lines().any(|line| line.trim() == "agent=1"), "{text}");
    Ok(())
}
