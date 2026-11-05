#!/bin/sh
# Sets up one hop from /state and runs sshd in the foreground, log on stderr.
#   bastion: user bastion-user, password bastion-pw
#   jump:    user jump-user, key /state/id_jump
#   target:  user target-user, key /state/id_target (held by the agent)
# Each role has its own host key /state/host_<role>.
set -eu
: "${ROLE:?ROLE fehlt (bastion, jump oder target)}"
user="${ROLE}-user"

install -m 600 "/state/host_${ROLE}" /etc/ssh/ssh_host_ed25519_key
install -m 644 "/state/host_${ROLE}.pub" /etc/ssh/ssh_host_ed25519_key.pub

# A restarted container keeps its user.
if ! id "$user" >/dev/null 2>&1; then
    adduser -D -s /bin/sh "$user"
    if [ "$ROLE" = bastion ]; then
        echo "${user}:bastion-pw" | chpasswd
    else
        # `*` instead of the locked `!` of adduser -D: no password, but sshd
        # still lets the key in.
        echo "${user}:*" | chpasswd -e
        install -d -m 700 -o "$user" -g "$user" "/home/${user}/.ssh"
        install -m 600 -o "$user" -g "$user" "/state/id_${ROLE}.pub" \
            "/home/${user}/.ssh/authorized_keys"
    fi
fi

exec /usr/sbin/sshd -D -e
