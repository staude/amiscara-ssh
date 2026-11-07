# Bastion of the test chain that wants a one-time code after the key
# (scripts/ssh-testkette.sh): publickey, then keyboard-interactive with TOTP
# through PAM.
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server libpam-google-authenticator \
 && rm -rf /var/lib/apt/lists/* /etc/ssh/ssh_host_* \
 && mkdir -p /run/sshd \
 && useradd -m -s /bin/sh otp-user \
 && usermod -p '*' otp-user
COPY sshd_config /etc/ssh/sshd_config
COPY pam-sshd /etc/pam.d/sshd
COPY entrypoint.sh /entrypoint.sh
EXPOSE 22
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
