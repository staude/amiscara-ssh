#!/bin/sh
# Installs AUTHORIZED_KEY for `tester` with the modes sshd insists on, then
# runs sshd in the foreground with its log on stderr.
set -eu
install -d -m 700 -o tester -g tester /home/tester/.ssh
printf '%s\n' "${AUTHORIZED_KEY:?AUTHORIZED_KEY fehlt}" > /home/tester/.ssh/authorized_keys
chown tester:tester /home/tester/.ssh/authorized_keys
chmod 600 /home/tester/.ssh/authorized_keys
exec /usr/sbin/sshd -D -e
