# OpenSSH from Alpine edge with the real ssh-agent and ssh-add. socat carries the agent socket out over an exec channel.
FROM alpine:edge
RUN apk add --no-cache openssh-server openssh-client socat \
 && ssh-keygen -A \
 && adduser -D -s /bin/sh zorg \
 && echo 'zorg:zorg-test' | chpasswd
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
