# One image for the three hops of the test chain (scripts/ssh-testkette.sh).
# ROLE (bastion, jump, target) picks host key, user and credentials.
FROM alpine:3.22
RUN apk add --no-cache openssh-server openssh-client \
 && rm -f /etc/ssh/ssh_host_*
COPY sshd_config /etc/ssh/sshd_config
COPY entrypoint.sh /entrypoint.sh
EXPOSE 22
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
