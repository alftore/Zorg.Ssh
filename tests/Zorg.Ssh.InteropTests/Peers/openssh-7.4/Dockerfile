# OpenSSH 7.4p1 from Debian 9. Stretch left the mirrors, so apt must use archive.debian.org.
FROM debian:stretch
RUN printf 'deb http://archive.debian.org/debian stretch main\ndeb http://archive.debian.org/debian-security stretch/updates main\n' > /etc/apt/sources.list \
 && apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd \
 && useradd -m -s /bin/sh zorg \
 && echo 'zorg:zorg-test' | chpasswd \
 && printf 'PasswordAuthentication yes\nLogLevel VERBOSE\n' >> /etc/ssh/sshd_config
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
