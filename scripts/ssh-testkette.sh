#!/usr/bin/env bash
# Local jump host chain for the chain tests: client -> bastion -> jump -> target,
# and client -> otp-bastion -> jump -> target with a one-time code.
#
#   scripts/ssh-testkette.sh start   keys, images and containers
#   scripts/ssh-testkette.sh stop    removes containers and networks
#   scripts/ssh-testkette.sh run     start, own ssh-agent, cargo test --test chain,
#                                    stop (also on failure)
#
# Only the bastion listens, on 127.0.0.1:${AMISCARA_SSH_CHAIN_PORT:-2223}, user
# `bastion-user` with password `bastion-pw`. Behind it `jump` (user `jump-user`,
# key id_jump) and `target` (user `target-user`, key id_target in the agent).
# The bastion with one-time code listens on 127.0.0.1:${AMISCARA_SSH_OTP_PORT:-2224},
# user `otp-user` with key id_otp and then the TOTP code of totp_secret.
# Keys, host keys, TOTP secret and known_hosts live in target/ssh-testkette/.
# Needs Docker.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
state="$root/target/ssh-testkette"
port="${AMISCARA_SSH_CHAIN_PORT:-2223}"
otp_port="${AMISCARA_SSH_OTP_PORT:-2224}"
export AMISCARA_SSH_CHAIN_PORT="$port" AMISCARA_SSH_OTP_PORT="$otp_port"
compose=(docker compose -f "$root/tests/kette/compose.yml")

keys() {
  mkdir -p "$state"
  chmod 700 "$state"
  for name in id_jump id_target id_otp host_bastion host_jump host_target host_otp; do
    if [ ! -f "$state/$name" ]; then
      ssh-keygen -q -t ed25519 -N '' -C "amiscara-ssh-chain-$name" -f "$state/$name"
    fi
  done
  if [ ! -f "$state/totp_secret" ]; then
    # 16 characters of Base32, as pam_google_authenticator reads them.
    # Process substitution, so the broken pipe of tr does not trip pipefail.
    head -c 16 < <(LC_ALL=C tr -dc 'A-Z2-7' </dev/urandom) >"$state/totp_secret"
  fi
  # One host key per role, or the check per hop would prove nothing.
  {
    echo "[127.0.0.1]:$port $(cut -d' ' -f1,2 "$state/host_bastion.pub")"
    echo "[127.0.0.1]:$otp_port $(cut -d' ' -f1,2 "$state/host_otp.pub")"
    echo "jump $(cut -d' ' -f1,2 "$state/host_jump.pub")"
    echo "target $(cut -d' ' -f1,2 "$state/host_target.pub")"
  } >"$state/known_hosts"
}

ready() {
  local logs
  logs="$("${compose[@]}" logs --no-log-prefix "$1" 2>&1)" || return 1
  grep -q 'Server listening' <<<"$logs"
}

start() {
  keys
  if ! "${compose[@]}" up -d --build --quiet-pull >"$state/compose-up.log" 2>&1; then
    cat "$state/compose-up.log" >&2
    return 1
  fi
  for hop in bastion otp-bastion jump target; do
    local ok=''
    for _ in $(seq 1 100); do
      if ready "$hop"; then ok=1; break; fi
      sleep 0.2
    done
    if [ -z "$ok" ]; then
      "${compose[@]}" logs >&2 || true
      echo "$hop ist nicht bereit." >&2
      return 1
    fi
  done
  echo "Kette läuft, Bastion auf 127.0.0.1:${port}, Bastion mit Einmalcode auf 127.0.0.1:${otp_port}."
}

stop() {
  "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
}

case "${1:-}" in
  start)
    start
    ;;
  stop)
    stop
    ;;
  run)
    agent_pid=''
    cleanup() {
      if [ -n "$agent_pid" ]; then kill "$agent_pid" 2>/dev/null || true; fi
      stop
    }
    trap cleanup EXIT
    start
    # An agent of its own with only the target key, so the tests never see
    # the keys of the user (and need no unsafe set_var).
    eval "$(ssh-agent -s)" >/dev/null
    agent_pid="$SSH_AGENT_PID"
    ssh-add -q "$state/id_target"
    cd "$root"
    cargo test --locked --test chain -- --ignored --test-threads=1
    ;;
  *)
    echo "Aufruf: $0 start|stop|run" >&2
    exit 2
    ;;
esac
