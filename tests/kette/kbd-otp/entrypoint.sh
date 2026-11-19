#!/bin/sh
# Sets up the bastion with password and one-time code by keyboard-interactive
# from /state and runs sshd in the foreground, log on stderr.
#   user kbd-otp-user, password kbd-otp-pw (set in the image), then the TOTP
#   code of /state/totp_secret (30 s, 6 digits, one step of skew either way;
#   a code may be used more than once, so tests can sign in twice in one step)
set -eu
home=/home/kbd-otp-user

install -m 600 /state/host_kbd_otp /etc/ssh/ssh_host_ed25519_key
install -m 644 /state/host_kbd_otp.pub /etc/ssh/ssh_host_ed25519_key.pub

rm -f "$home/.google_authenticator"
{
    # The file of the script has no line break at the end.
    printf '%s\n' "$(cat /state/totp_secret)"
    echo '" TOTP_AUTH'
    echo '" WINDOW_SIZE 3'
} >"$home/.google_authenticator"
chown kbd-otp-user:kbd-otp-user "$home/.google_authenticator"
chmod 400 "$home/.google_authenticator"

exec /usr/sbin/sshd -D -e
