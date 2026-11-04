import socket, threading, paramiko

HOST_KEY = paramiko.RSAKey.generate(2048)

class Server(paramiko.ServerInterface):
    def check_auth_password(self, username, password):
        ok = username == "zorg" and password == "zorg-test"
        return paramiko.AUTH_SUCCESSFUL if ok else paramiko.AUTH_FAILED
    def get_allowed_auths(self, username): return "password"
    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    def check_channel_exec_request(self, channel, command):
        # Paramiko replies to the request after this returns, so the work runs on another thread.
        def run():
            channel.send(f"paramiko {paramiko.__version__}\n".encode())
            channel.send_exit_status(0)
            channel.close()
        threading.Timer(0.05, run).start()
        return True

def serve(conn):
    t = paramiko.Transport(conn)
    t.add_server_key(HOST_KEY)
    try:
        t.start_server(server=Server())
        # Keep the reference: Paramiko holds channels weakly, and collecting one closes it.
        channel = t.accept(30)
        while t.is_active():
            t.join(1)
    except Exception as e:
        print(f"connection failed: {e}", flush=True)

s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("", 22))
s.listen(16)
print(f"Server listening: paramiko {paramiko.__version__}", flush=True)
while True:
    c, _ = s.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
