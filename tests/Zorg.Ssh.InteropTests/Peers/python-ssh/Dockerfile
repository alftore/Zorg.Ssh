# AsyncSSH and Paramiko servers. One image; pick with the command:
#   python /app/server_asyncssh.py   (default)
#   python /app/server_paramiko.py
FROM python:3.13-slim
RUN pip install --no-cache-dir asyncssh paramiko ssh-audit
COPY server_asyncssh.py server_paramiko.py client_asyncssh.py client_paramiko.py relay.py /app/
EXPOSE 22
CMD ["python", "-u", "/app/server_asyncssh.py"]
