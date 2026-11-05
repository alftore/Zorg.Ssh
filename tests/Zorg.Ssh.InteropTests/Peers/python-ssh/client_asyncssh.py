import asyncio, sys, asyncssh

async def main(host, port):
    async with asyncssh.connect(host, port, username="alice", password="pw", known_hosts=None, client_keys=None) as conn:
        result = await conn.run("hello")
        print(result.stdout, end="")
        print("exit", result.exit_status)

asyncio.run(main(sys.argv[1], int(sys.argv[2])))
