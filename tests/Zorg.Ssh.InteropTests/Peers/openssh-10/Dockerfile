# OpenSSH from Alpine edge (10.6p1 at the time of spike S3).
FROM alpine:edge
RUN apk add --no-cache openssh-server openssh-sftp-server \
 && ssh-keygen -A \
 && adduser -D -s /bin/sh zorg \
 && echo 'zorg:zorg-test' | chpasswd \
 && printf 'PasswordAuthentication yes\nLogLevel VERBOSE\n' >> /etc/ssh/sshd_config
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
