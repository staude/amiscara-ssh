# Bastion of the test chain that takes the password only by
# keyboard-interactive (scripts/ssh-testkette.sh): PasswordAuthentication is
# off, PAM (pam_unix of Debian) asks for the password instead.
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server \
 && rm -rf /var/lib/apt/lists/* /etc/ssh/ssh_host_* \
 && mkdir -p /run/sshd \
 && useradd -m -s /bin/sh kbd-user \
 && echo 'kbd-user:kbd-pw' | chpasswd
COPY sshd_config /etc/ssh/sshd_config
COPY entrypoint.sh /entrypoint.sh
EXPOSE 22
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
