# Security

**Zorg.Ssh is pre-release software and hasn't had an external security review.** Agents helped write it, and the reviews so far were internal. Don't use it to protect anything that matters yet. To report a problem, follow [SECURITY.md](../SECURITY.md).

## The four guarantees

These are the rules the library is built around. Each has tests, and a change that weakens one needs a design decision. They're goals backed by tests, not proofs.

1. **No message is acted on in a state that doesn't allow it.** One table, `Transport/MessagePolicy`, decides which message may arrive when. The default is deny. A connection message before login ends the connection.
2. **Nothing proceeds on an unverified host key or unauthenticated user.** There's no default host key policy. Anything that weakens a check has `Unsafe` in its name: `HostKeyPolicy.AcceptAnyUnsafe` and the `addUnknownHostsUnsafe` argument. On the server, a public key handler's answer counts only once the client's signature has been verified.
3. **A hostile peer can't cause unbounded memory, a hang or an unhandled exception type.** Buffers, queues and counts have limits, and waits can be cancelled. Failures a peer causes reach you as `SshException` or a derived type.
4. **Secrets never reach logs or exception messages, and are zeroed after use.** See the limits on this under [Secrets](#secrets).

Published SSH advisories in other implementations each have a named regression test. They include Terrapin, Erlang CVE-2025-32433 and CVE-2025-46712, AsyncSSH CVE-2023-46445 and CVE-2023-46446, Go CVE-2025-22869 and CVE-2026-39828, and libssh CVE-2025-8277 and CVE-2026-59848.

### Secrets

Guarantee 4 has limits you should know about:

- Passwords, passphrases and keyboard-interactive answers enter the library as .NET strings, and `SshPasswordRequest.Password` gives one to your handler. Strings can't be zeroed, so these stay in memory until the garbage collector reuses it.
- `FromPrivateKey` holds the key text as a string, for the same reason.
- ChaCha20-Poly1305 leaves each packet's one-time Poly1305 key on the heap until it's collected. That key authenticates a single packet, which has already been sent or accepted by then.
- The guarantee covers what the library logs and throws. It can't cover what your own handlers log.

## Defaults

| Setting | Default |
|---|---|
| Host key policy | None: you must choose one |
| Client connect, key exchange and login | 30 seconds in total |
| `ExecuteAsync` output | 64 MiB per stream |
| SFTP `ReadAllBytesAsync` | 256 MiB |
| SFTP entries per listing or tree | 1,000,000 |
| SFTP tree depth | 64 levels |
| SFTP requests in flight per transfer | 64, of 32 KiB each |
| Largest SSH packet accepted | 256 KiB |
| Channel window | 2 MiB, with packets of 32 KiB |
| Rekey | After 1 GiB or 2^31 packets in one direction, or 1 hour |
| Time allowed for a rekey | 60 seconds |
| Server address | Loopback |
| Server limits | See [server.md](server.md#limits) |
| Unauthenticated connections per source address | 5, counted by IPv4 address or IPv6 /64 |
| Idle logged-in connection (no open channel) | Not closed by default. `IdleTimeout` sets it |

Strict key exchange, the fix for Terrapin, is used whenever the peer supports it. Against an old server without it, the connection goes ahead without that protection.

## Algorithms

The lists below are fixed, in preference order. **There's no public option to change them**, on the client or the server. To force an algorithm, set it on the other side, as [benchmarks.md](benchmarks.md) does with `sshd -o Ciphers=...`.

Key exchange:

1. `mlkem768x25519-sha256`
2. `sntrup761x25519-sha512`
3. `sntrup761x25519-sha512@openssh.com`
4. `curve25519-sha256`
5. `curve25519-sha256@libssh.org`
6. `ecdh-sha2-nistp256`
7. `ecdh-sha2-nistp384`
8. `ecdh-sha2-nistp521`

Host keys and public key signatures:

1. `ssh-ed25519`
2. `ecdsa-sha2-nistp256`
3. `ecdsa-sha2-nistp384`
4. `ecdsa-sha2-nistp521`
5. `rsa-sha2-512`
6. `rsa-sha2-256`

Ciphers, on a machine with AES hardware:

1. `aes256-gcm@openssh.com`
2. `aes128-gcm@openssh.com`
3. `chacha20-poly1305@openssh.com`
4. `aes256-ctr`
5. `aes128-ctr`

Without AES hardware, `chacha20-poly1305@openssh.com` moves to the front.

MACs, used only with the CTR ciphers: `hmac-sha2-512-etm@openssh.com`, then `hmac-sha2-256-etm@openssh.com`.

Compression: `none` only.

Not offered: `ssh-rsa` with SHA-1, `ssh-dss`, CBC ciphers, `diffie-hellman-*` key exchange and non-EtM MACs. A server that offers only those fails with `SshNegotiationException`.

BouncyCastle provides Ed25519, X25519, ML-KEM, sntrup761 and ChaCha20-Poly1305 where the .NET libraries don't. Its code hasn't been reviewed as part of this project. See [dependencies.md](dependencies.md).

## Out of scope

Not implemented in this version:

- **SCP**, and it won't be added. It's a shell-command protocol with a history of path injection. Use SFTP.
- **Compression**, which is left out of version 1. OpenSSH 10.6 disabled LZ77 in compression because of a side channel.
- Remote forwarding on the server: it refuses every `tcpip-forward` request.
- Agent forwarding. Logging in through a local ssh-agent is supported.
- User certificates on the server: it refuses them. The client can log in with one, and trusts host certificates through `@cert-authority` lines.
- Following `ProxyJump` from a config file. `SshClientOptions.FromConfig` reads a subset of `~/.ssh/config` and refuses such a host. Use `SshClientOptions.JumpHost` instead.
- X11 forwarding, GSSAPI, host-based login, security keys (`sk-`), PKCS#11 and ML-DSA signatures.
- Legacy algorithms. Old network equipment that needs them won't connect.
- Keyboard-interactive login and password changes on the server side.
- Changing an expired password from the client: it fails with `SshAuthenticationException`.
- SFTP versions other than 3.

The agent, certificates and config parsing are planned. Nothing here is a promise of a date.

## Unverified

What the tests do cover: the interop tests run against OpenSSH 10.x, OpenSSH 7.4 and Dropbear for login and exec, AsyncSSH and Paramiko servers for exec, and OpenSSH 10.x and 7.4 for SFTP. Real OpenSSH clients run against the server for login, exec, every default key exchange and every cipher.

What hasn't been checked:

- **No external security review** of any part, including the transport and the server. There has been no penetration test or audit.
- **Fuzzing is shallow.** Besides the hand-written hostile-input tests, a seeded fuzzer attacks the decoders that read bytes or text from a peer, a file or a local client (the packet reader, `KEXINIT`, public keys and certificates, key files, `known_hosts`, `ssh_config`, the SFTP readers and server dispatch, SOCKS, the agent replies and public key requests). It checks for a wrong exception type, a hang and a large allocation, and a normal test pass runs a short fixed-seed round of it. It isn't coverage-guided, each target has had minutes of runs rather than days, it never runs a whole handshake, and it can't see a stack overflow or an allocation made on another thread. `CONTRIBUTING.md` says how to run and replay it.
- **Timing side channels** haven't been measured, in this code or in BouncyCastle.
- **Zeroing** is done in code, but nothing proves that no copy remains, and a garbage collector can move memory.
- **The server against scanners.** `ssh-audit` reports no failures, and tests check that. Terrapin-Scanner itself hasn't been run, though `ssh-audit` checks for the same flaw.
- **SFTP against other servers.** Only OpenSSH's `sftp-server` has been tested. Commercial and appliance servers haven't, and neither has the OpenSSH server for Windows.
- **Real network equipment**, and its quirks.
- **Native AOT** is covered by a smoke test of the algorithms and one in-memory session (a command, an SFTP round trip, the agent protocol and `ssh_config` parsing), not by a real network connection.
- **Other platforms.** Day-to-day work happens on Windows x64, with peers in Linux containers. The unit and interop suites also run in a Linux container (`scripts/test-linux.sh`) on Alpine (musl) and Ubuntu (glibc), on x64 only. The CI workflow also targets Ubuntu, but hasn't run yet. macOS and Arm haven't been tried.
- **Long-running connections.** Rekeying has been tested, but not connections left up for days.
- **The public API** can still change before 1.0.
