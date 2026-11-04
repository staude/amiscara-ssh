#!/usr/bin/env bash
# Local SSH server for the container tests.
#
#   scripts/ssh-testserver.sh start   key, image and container; nothing if it runs
#   scripts/ssh-testserver.sh stop    removes the container
#
# The server listens on 127.0.0.1:${AMISCARA_SSH_TEST_PORT:-2222}, user
# `tester`, password `tester-pw`, key target/ssh-testserver/id_ed25519.
# Then: cargo test -- --ignored
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
name=amiscara-ssh-test
image=amiscara-ssh-test
port="${AMISCARA_SSH_TEST_PORT:-2222}"
keys="$root/target/ssh-testserver"

case "${1:-}" in
  start)
    # Keep a running container only if it fits: same port, key still there
    # (`cargo clean` removes it). Otherwise start afresh.
    if [ -n "$(docker ps -q --filter "name=^/${name}$")" ] \
      && [ -f "$keys/id_ed25519" ] \
      && docker port "$name" 22/tcp | grep -qx "127.0.0.1:${port}"; then
      echo "$name läuft schon auf 127.0.0.1:${port}."
      exit 0
    fi
    docker rm -f "$name" >/dev/null 2>&1 || true
    mkdir -p "$keys"
    if [ ! -f "$keys/id_ed25519" ]; then
      ssh-keygen -q -t ed25519 -N '' -C amiscara-ssh-test -f "$keys/id_ed25519"
    fi
    docker build -q -t "$image" "$root/tests/sshd" >/dev/null
    docker run -d --name "$name" -p "127.0.0.1:${port}:22" \
      -e "AUTHORIZED_KEY=$(cat "$keys/id_ed25519.pub")" "$image" >/dev/null
    for _ in $(seq 1 50); do
      if grep -q 'Server listening' <<<"$(docker logs "$name" 2>&1)"; then
        echo "$name läuft auf 127.0.0.1:${port}."
        exit 0
      fi
      sleep 0.2
    done
    docker logs "$name" >&2 || true
    echo "$name ist nicht bereit." >&2
    exit 1
    ;;
  stop)
    docker rm -f "$name" >/dev/null 2>&1 || true
    ;;
  *)
    echo "Aufruf: $0 start|stop" >&2
    exit 2
    ;;
esac
