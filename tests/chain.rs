//! Tests against the local jump host chain (bastion -> jump -> target). Run
//! them with the chain and an agent of their own:
//!
//! ```sh
//! scripts/ssh-testkette.sh run
//! ```
//!
//! Index 0 is the bastion, 1 the jump, 2 the target. The second bastion,
//! `otp-bastion`, wants a one-time code after the key, so its routes ask the
//! test's prompter. The tests stop and start containers, so they run one at a
//! time (`--test-threads=1`).

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use amiscara_ssh::{
    HopEvent, HopFailure, HopState, HostKeyPolicy, Identity, KeyboardAnswer, KeyboardInteractive,
    KeyboardPrompt, PoolConfig, PromptFuture, PtySize, Route, Session, SessionPool, ShellEvent,
    SshError, SshTarget, Zeroizing, keys,
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

fn otp_port() -> u16 {
    std::env::var("AMISCARA_SSH_OTP_PORT")
        .ok()
        .and_then(|port| port.parse().ok())
        .unwrap_or(2224)
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
        keyboard_interactive: None,
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
        keyboard_interactive: None,
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
        keyboard_interactive: None,
    }
}

fn chain() -> Route {
    Route {
        jumps: vec![bastion(), jump()],
        target: target(),
    }
}

/// The current code of the bastion with one-time code.
fn totp() -> Result<String, Box<dyn std::error::Error>> {
    let secret = std::fs::read_to_string(state().join("totp_secret"))?;
    let secret = totp_rs::Secret::try_from_base32(secret.trim())?;
    // 80 bits are too short for the RFC check, but what the bastion uses.
    let totp = totp_rs::Builder::new()
        .with_secret(secret)
        .build_noncompliant();
    Ok(totp.generate_current().to_string())
}

/// How the test prompter answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answer {
    /// The current code.
    Code,
    /// A wrong code first, then the current one.
    WrongThenCode,
    /// Cancels the question.
    Cancel,
    /// Never answers.
    Hang,
}

/// A prompter that answers like a user typing the code and remembers every
/// question.
#[derive(Debug)]
struct Prompter {
    answer: Answer,
    keep_open: Option<Duration>,
    delay: Duration,
    asked: Mutex<Vec<KeyboardPrompt>>,
}

impl Prompter {
    fn new(answer: Answer) -> Arc<Self> {
        Self::with(answer, None, Duration::ZERO)
    }

    fn with(answer: Answer, keep_open: Option<Duration>, delay: Duration) -> Arc<Self> {
        Arc::new(Self {
            answer,
            keep_open,
            delay,
            asked: Mutex::new(Vec::new()),
        })
    }

    fn asked(&self) -> Vec<KeyboardPrompt> {
        self.asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl KeyboardInteractive for Prompter {
    fn ask(&self, prompt: KeyboardPrompt) -> PromptFuture {
        let count = {
            let mut asked = self.asked.lock().unwrap_or_else(PoisonError::into_inner);
            asked.push(prompt);
            asked.len()
        };
        let code = match self.answer {
            Answer::Cancel => None,
            Answer::Hang => return Box::pin(std::future::pending()),
            Answer::Code => totp().ok(),
            Answer::WrongThenCode if count == 1 => totp().ok().map(|code| {
                // Shifted by one in every digit: never a code of the window.
                code.chars()
                    .map(|c| {
                        c.to_digit(10)
                            .map_or(c, |d| char::from(b'0' + ((d + 1) % 10) as u8))
                    })
                    .collect()
            }),
            Answer::WrongThenCode => totp().ok(),
        };
        let keep_open = self.keep_open;
        let delay = self.delay;
        Box::pin(async move {
            tokio::time::sleep(delay).await;
            code.map(|code| KeyboardAnswer {
                responses: vec![Zeroizing::new(code)],
                keep_open,
            })
        })
    }
}

fn otp_bastion(prompter: &Arc<Prompter>) -> SshTarget {
    let prompter: Arc<dyn KeyboardInteractive> = Arc::clone(prompter) as _;
    SshTarget {
        host: "127.0.0.1".into(),
        port: otp_port(),
        user: "otp-user".into(),
        identity: Identity::File {
            path: state().join("id_otp"),
            passphrase: None,
        },
        host_key: strict(),
        agent_forward: false,
        keyboard_interactive: Some(prompter),
    }
}

/// otp-bastion -> jump -> target.
fn otp_chain(prompter: &Arc<Prompter>) -> Route {
    Route {
        jumps: vec![otp_bastion(prompter), jump()],
        target: target(),
    }
}

/// Connects until the containers are back after a restart.
async fn connect_retrying(
    pool: &SessionPool,
    route: &Route,
) -> Result<amiscara_ssh::Lease, SshError> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        match pool.connect(route).await {
            Ok(lease) => return Ok(lease),
            Err(err) if tokio::time::Instant::now() < deadline && !err.needs_user() => {
                eprintln!("noch nicht bereit: {err}");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(err) => return Err(err),
        }
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
async fn sftp_on_target_over_two_jumps() -> TestResult {
    let pool = SessionPool::new(PoolConfig::default());
    let lease = pool.connect(&chain()).await?;
    let sftp = lease.open_sftp().await?;
    assert_eq!(sftp.canonicalize(".").await?, "/home/target-user");
    // A fresh account: no entries besides the hidden ones of adduser.
    let entries: Vec<String> = sftp
        .read_dir(".")
        .await?
        .map(|entry| entry.file_name())
        .collect();
    assert!(
        entries.iter().all(|name| name.starts_with('.')),
        "{entries:?}"
    );
    sftp.close().await?;
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

#[tokio::test]
#[ignore = "braucht scripts/ssh-testkette.sh run"]
async fn one_time_code_is_asked_once_and_only_for_the_bastion() -> TestResult {
    let pool = SessionPool::new(PoolConfig::default());
    let mut events = pool.subscribe();
    let prompter = Prompter::new(Answer::Code);
    let route = otp_chain(&prompter);
    let lease = pool.connect(&route).await?;

    let asked = prompter.asked();
    assert_eq!(asked.len(), 1, "{asked:?}");
    let prompt = &asked[0];
    assert_eq!(prompt.index, 0);
    assert_eq!(prompt.route, route.labels());
    assert_eq!(prompt.route.len(), 3);
    assert_eq!(
        prompt.route[0],
        format!("otp-user@127.0.0.1:{}", otp_port())
    );
    assert_eq!(prompt.attempt, 1);
    assert_eq!(prompt.prompts.len(), 1, "{prompt:?}");
    assert!(!prompt.prompts[0].echo, "{prompt:?}");

    let seen = drain(&mut events);
    let waiting: Vec<usize> = seen
        .iter()
        .filter(|(_, state)| *state == HopState::AwaitingInput)
        .map(|(index, _)| *index)
        .collect();
    assert_eq!(waiting, vec![0], "{seen:?}");
    shell_line(&lease, "hostname", "target").await?;
    Ok(())
}

#[tokio::test]
#[ignore = "braucht scripts/ssh-testkette.sh run"]
async fn kept_open_bastion_needs_no_new_code_until_its_time_is_up() -> TestResult {
    let pool = SessionPool::new(PoolConfig::default());
    let mut events = pool.subscribe();
    let prompter = Prompter::with(Answer::Code, Some(Duration::from_secs(3)), Duration::ZERO);
    let route = otp_chain(&prompter);

    let lease = pool.connect(&route).await?;
    drain(&mut events);
    drop(lease);
    let seen = wait_closed(&mut events, &[1, 2], Duration::from_secs(10)).await?;
    assert!(states_of(&seen, 0).is_empty(), "bastion closed: {seen:?}");

    let again = pool.connect(&route).await?;
    let seen = drain(&mut events);
    assert_eq!(states_of(&seen, 0), vec![&HopState::Reused], "{seen:?}");
    assert_eq!(prompter.asked().len(), 1, "asked again within the time");
    shell_line(&again, "hostname", "target").await?;

    drop(again);
    let dropped = Instant::now();
    wait_closed(&mut events, &[0], Duration::from_secs(10)).await?;
    let waited = dropped.elapsed();
    assert!(
        waited >= Duration::from_millis(2500),
        "closed after {waited:?}"
    );

    let after = pool.connect(&route).await?;
    assert_eq!(prompter.asked().len(), 2, "no new code after the time");
    drop(after);
    Ok(())
}

#[tokio::test]
#[ignore = "braucht scripts/ssh-testkette.sh run"]
async fn without_grace_all_close_and_close_idle_ends_the_wait() -> TestResult {
    let config = PoolConfig {
        code_grace: Duration::ZERO,
        ..PoolConfig::default()
    };
    let pool = SessionPool::new(config);
    let mut events = pool.subscribe();
    let prompter = Prompter::new(Answer::Code);
    let lease = pool.connect(&otp_chain(&prompter)).await?;
    drain(&mut events);
    drop(lease);
    wait_closed(&mut events, &[0, 1, 2], Duration::from_secs(10)).await?;

    // With the default grace the bastion waits, until close_idle.
    let pool = SessionPool::new(PoolConfig::default());
    let mut events = pool.subscribe();
    let lease = pool.connect(&otp_chain(&prompter)).await?;
    drain(&mut events);
    drop(lease);
    let seen = wait_closed(&mut events, &[1, 2], Duration::from_secs(10)).await?;
    assert!(states_of(&seen, 0).is_empty(), "bastion closed: {seen:?}");
    assert_eq!(pool.close_idle(), 1);
    wait_closed(&mut events, &[0], Duration::from_secs(5)).await?;
    assert_eq!(pool.close_idle(), 0);
    Ok(())
}

#[tokio::test]
#[ignore = "braucht scripts/ssh-testkette.sh run"]
async fn cancelled_code_leaves_nothing_open_and_the_next_try_asks_again() -> TestResult {
    let pool = SessionPool::new(PoolConfig::default());
    let mut events = pool.subscribe();

    let cancel = Prompter::new(Answer::Cancel);
    match pool.connect(&otp_chain(&cancel)).await {
        Err(SshError::Hop { index, source, .. }) => {
            assert_eq!(index, 0);
            assert!(matches!(*source, SshError::Cancelled(_)), "{source}");
        }
        Err(other) => return Err(format!("expected Hop 0, got {other}").into()),
        Ok(_) => return Err("connected without a code".into()),
    }
    let seen = drain(&mut events);
    assert!(
        seen.contains(&(0, HopState::Failed(HopFailure::Cancelled))),
        "{seen:?}"
    );
    assert_eq!(pool.close_idle(), 0, "something stayed in the pool");

    // The app gives up while the question is open.
    let hang = Prompter::new(Answer::Hang);
    let given_up =
        tokio::time::timeout(Duration::from_secs(1), pool.connect(&otp_chain(&hang))).await;
    assert!(given_up.is_err(), "the hanging question ended by itself");
    assert_eq!(hang.asked().len(), 1);
    assert_eq!(pool.close_idle(), 0, "something stayed in the pool");

    let code = Prompter::new(Answer::Code);
    let lease = pool.connect(&otp_chain(&code)).await?;
    assert_eq!(code.asked().len(), 1);
    shell_line(&lease, "hostname", "target").await?;
    Ok(())
}

#[tokio::test]
#[ignore = "braucht scripts/ssh-testkette.sh run"]
async fn behind_a_kept_bastion_only_the_rest_is_rebuilt() -> TestResult {
    let pool = SessionPool::new(PoolConfig::default());
    let mut events = pool.subscribe();
    let prompter = Prompter::new(Answer::Code);
    let route = otp_chain(&prompter);
    let old = pool.connect(&route).await?;
    drain(&mut events);

    // The jump behind the bastion goes away.
    compose(&["kill", "jump"])?;
    let closed = wait_closed(&mut events, &[1, 2], Duration::from_secs(30)).await;
    compose(&["start", "jump"])?;
    let closed = closed?;
    assert!(states_of(&closed, 0).is_empty(), "{closed:?}");
    drop(old);

    drain(&mut events);
    let new = connect_retrying(&pool, &route).await?;
    let seen = drain(&mut events);
    assert!(
        states_of(&seen, 0).iter().all(|s| **s == HopState::Reused),
        "{seen:?}"
    );
    assert_eq!(prompter.asked().len(), 1, "a new code for the old bastion");
    shell_line(&new, "hostname", "target").await?;
    drop(new);

    // The bastion itself restarts: exactly one new code.
    compose(&["restart", "otp-bastion"])?;
    wait_closed(&mut events, &[0], Duration::from_secs(30)).await?;
    let after = connect_retrying(&pool, &route).await?;
    assert_eq!(prompter.asked().len(), 2, "{:?}", prompter.asked());
    shell_line(&after, "hostname", "target").await?;
    Ok(())
}

#[tokio::test]
#[ignore = "braucht scripts/ssh-testkette.sh run"]
async fn wrong_code_can_be_typed_again_on_the_same_connection() -> TestResult {
    let pool = SessionPool::new(PoolConfig::default());
    let mut events = pool.subscribe();
    let prompter = Prompter::new(Answer::WrongThenCode);
    let lease = pool.connect(&otp_chain(&prompter)).await?;
    let attempts: Vec<u32> = prompter.asked().iter().map(|p| p.attempt).collect();
    assert_eq!(attempts, vec![1, 2]);
    let seen = drain(&mut events);
    // One connection: a single Connecting for the bastion.
    let bastion = states_of(&seen, 0);
    assert_eq!(
        bastion
            .iter()
            .filter(|s| ***s == HopState::Connecting)
            .count(),
        1,
        "{seen:?}"
    );
    shell_line(&lease, "hostname", "target").await?;
    Ok(())
}

#[tokio::test]
#[ignore = "braucht scripts/ssh-testkette.sh run"]
async fn waiting_for_the_code_does_not_count_towards_the_limit() -> TestResult {
    let config = PoolConfig {
        connect_timeout: Duration::from_secs(2),
        ..PoolConfig::default()
    };
    let pool = SessionPool::new(config);
    let prompter = Prompter::with(Answer::Code, None, Duration::from_secs(3));
    let lease = pool.connect(&otp_chain(&prompter)).await?;
    shell_line(&lease, "hostname", "target").await?;
    Ok(())
}
