#!/bin/sh
# Sets up the bastion with one-time code from /state and runs sshd in the
# foreground, log on stderr.
#   user otp-user, key /state/id_otp, then the TOTP code of
#   /state/totp_secret (30 s, 6 digits, one step of skew either way; a code
#   may be used more than once, so tests can sign in twice in one step)
set -eu
home=/home/otp-user

install -m 600 /state/host_otp /etc/ssh/ssh_host_ed25519_key
install -m 644 /state/host_otp.pub /etc/ssh/ssh_host_ed25519_key.pub
install -d -m 700 -o otp-user -g otp-user "$home/.ssh"
install -m 600 -o otp-user -g otp-user /state/id_otp.pub "$home/.ssh/authorized_keys"

rm -f "$home/.google_authenticator"
{
    # The file of the script has no line break at the end.
    printf '%s\n' "$(cat /state/totp_secret)"
    echo '" TOTP_AUTH'
    echo '" WINDOW_SIZE 3'
} >"$home/.google_authenticator"
chown otp-user:otp-user "$home/.google_authenticator"
chmod 400 "$home/.google_authenticator"

exec /usr/sbin/sshd -D -e
