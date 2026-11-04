# tinyssh is inetd-style, so busybox tcpsvd supplies the listener.
FROM alpine:edge
RUN apk add --no-cache tinyssh busybox-extras \
 && adduser -D -s /bin/sh zorg \
 && passwd -u zorg \
 && mkdir -p /home/zorg/.ssh /etc/tinyssh \
 && tinysshd-makekey /etc/tinyssh/sshkeydir
EXPOSE 22
CMD ["tcpsvd", "-v", "0.0.0.0", "22", "/usr/sbin/tinysshd", "-v", "/etc/tinyssh/sshkeydir"]
