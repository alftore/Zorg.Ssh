# Dropbear from Alpine edge (2026.94 at the time of spike S3). Much faster to build than from source.
FROM alpine:edge
RUN apk add --no-cache dropbear openssh-sftp-server \
 && adduser -D -s /bin/sh zorg \
 && echo 'zorg:zorg-test' | chpasswd \
 && mkdir -p /etc/dropbear
EXPOSE 22
# -R creates host keys on demand, -F foreground, -E logs to stderr.
CMD ["/usr/sbin/dropbear", "-R", "-F", "-E", "-p", "22"]
