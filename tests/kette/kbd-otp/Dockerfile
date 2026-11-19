# Bastion of the test chain that asks for the password and then a one-time
# code in the same keyboard-interactive sign-in (scripts/ssh-testkette.sh):
# PasswordAuthentication is off, PAM asks for the password (pam_unix of
# Debian) and then the TOTP code.
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server libpam-google-authenticator \
 && rm -rf /var/lib/apt/lists/* /etc/ssh/ssh_host_* \
 && mkdir -p /run/sshd \
 && useradd -m -s /bin/sh kbd-otp-user \
 && echo 'kbd-otp-user:kbd-otp-pw' | chpasswd
COPY sshd_config /etc/ssh/sshd_config
COPY pam-sshd /etc/pam.d/sshd
COPY entrypoint.sh /entrypoint.sh
EXPOSE 22
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
