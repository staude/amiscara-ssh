# Local SSH server for the container tests (scripts/ssh-testserver.sh).
# User `tester` signs in with the generated key or the password `tester-pw`.
# The tests run in parallel and one of them fails a password on purpose, so
# sshd neither drops parallel sign-ins (MaxStartups) nor penalises the source
# after a failure (PerSourcePenalties). Alpine ships AllowTcpForwarding no,
# the forwarding tests need it.
FROM alpine:3.22
RUN apk add --no-cache openssh-server \
 && ssh-keygen -A \
 && adduser -D -s /bin/sh tester \
 && echo 'tester:tester-pw' | chpasswd \
 && printf 'PasswordAuthentication yes\nPubkeyAuthentication yes\nKbdInteractiveAuthentication no\nMaxStartups 100\nPerSourcePenalties no\nAllowTcpForwarding yes\n' > /tmp/head \
 && cat /tmp/head /etc/ssh/sshd_config > /tmp/sshd_config \
 && mv /tmp/sshd_config /etc/ssh/sshd_config \
 && rm /tmp/head
COPY entrypoint.sh /entrypoint.sh
EXPOSE 22
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
