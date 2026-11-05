# Lets tools in this container reach an SSH server on the test host, for hosts where containers can't
# connect out to it. The host connects in on port 22 and waits. A local tool connects to 127.0.0.1:2222
# and is joined to the next waiting host connection. The first connection in is the harness checking
# that the container is up, so it gets a banner and is closed.
import queue, socket, threading

waiting = queue.Queue()

def listen(address, port):
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((address, port))
    server.listen(128)
    return server

def pump(source, target):
    try:
        while True:
            data = source.recv(65536)
            if not data:
                break
            target.sendall(data)
    except OSError:
        pass
    for s in (source, target):
        try:
            s.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

def from_host():
    server = listen("0.0.0.0", 22)
    probe, _ = server.accept()
    probe.sendall(b"SSH-2.0-relay\r\n")
    probe.close()
    while True:
        connection, _ = server.accept()
        waiting.put(connection)

def from_tools():
    server = listen("127.0.0.1", 2222)
    print("Server listening: relay", flush=True)
    while True:
        local, _ = server.accept()
        remote = waiting.get(timeout=60)
        threading.Thread(target=pump, args=(local, remote), daemon=True).start()
        threading.Thread(target=pump, args=(remote, local), daemon=True).start()

threading.Thread(target=from_host, daemon=True).start()
from_tools()
