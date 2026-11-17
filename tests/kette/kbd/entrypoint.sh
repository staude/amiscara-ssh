#!/bin/sh
# Sets up the bastion with password by keyboard-interactive from /state and
# runs sshd in the foreground, log on stderr.
#   user kbd-user, password kbd-pw (set in the image)
set -eu
install -m 600 /state/host_kbd /etc/ssh/ssh_host_ed25519_key
install -m 644 /state/host_kbd.pub /etc/ssh/ssh_host_ed25519_key.pub
exec /usr/sbin/sshd -D -e
