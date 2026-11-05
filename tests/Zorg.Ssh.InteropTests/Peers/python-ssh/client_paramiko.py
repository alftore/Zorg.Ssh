import sys, paramiko

host, port = sys.argv[1], int(sys.argv[2])
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect(host, port=port, username="alice", password="pw", look_for_keys=False, allow_agent=False)
_, stdout, _ = client.exec_command("hello")
print(stdout.read().decode(), end="")
print("exit", stdout.channel.recv_exit_status())
client.close()
