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

The lists below are the defaults, in preference order, on the client and the server. `Algorithms` on `SshClientOptions` and `SshServerOptions` can narrow them, for example to meet a policy; a name the library doesn't implement is refused when you connect or start.

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

MACs, used only with the CTR ciphers:

1. `hmac-sha2-512-etm@openssh.com`
2. `hmac-sha2-256-etm@openssh.com`
3. `hmac-sha2-512`
4. `hmac-sha2-256`

The last two are encrypt-and-MAC (RFC 6668): the MAC covers the plaintext, and the packet length is encrypted with the body. They come after both EtM MACs, as in OpenSSH 10's client order, and with the default cipher order they're used only against a peer that has no AEAD cipher and no EtM MAC. Dropbear has never had an EtM MAC, and some appliances offer only these.

Why they're acceptable:

- With CTR, encrypt-and-MAC has no known attack. The Albrecht–Paterson–Watson plaintext recovery (2009) needs CBC, which isn't offered. Terrapin's authors (USENIX Security 2024) list CTR with encrypt-and-MAC as not affected, and strict key exchange is negotiated and enforced exactly as with the other ciphers.
- HMAC-SHA-2 doesn't rely on SHA-2's collision resistance.
- The length is the only value read before the MAC is checked, because the reader needs it to know how much to read. It's checked against the 256 KiB limit and the block shape from the first 16 bytes, before anything more is read or allocated, and a packet that fails its MAC is zeroed and ends the connection. Nothing else from the packet is acted on until the MAC passes, and the comparison is constant-time.

Compression: `none` only.

Not offered by default: `ssh-rsa` with SHA-1, `diffie-hellman-*` key exchange and `hmac-sha1`. `SshAlgorithms.LegacyUnsafe` adds them, as the next section says. Never offered: `diffie-hellman-group1-sha1`, `diffie-hellman-group-exchange-*`, `ssh-dss`, `3des-cbc`, every CBC cipher, arcfour and MD5. A server that offers only those fails with `SshNegotiationException`, whose message points at `LegacyUnsafe` when that would help.

### Legacy algorithms

`SshAlgorithms.LegacyUnsafe` is the defaults with these appended, last in each list:

- Key exchange: `diffie-hellman-group14-sha256`, `diffie-hellman-group16-sha512` (RFC 8268), `diffie-hellman-group14-sha1` (RFC 4253), on the RFC 3526 2048-bit and 4096-bit groups.
- Host keys and user signatures: `ssh-rsa`, RSA with SHA-1.
- MACs: `hmac-sha1-etm@openssh.com`, `hmac-sha1`.

It's for network equipment, BMCs and old servers that have nothing better, such as HPE iLO 4 and 5, classic Cisco IOS, older Dropbear and RHEL 6. A peer that has anything better still gets it: the legacy names come last, and each side's `KEXINIT` is in the signed exchange hash, so a man in the middle can't strip the modern names. Choosing a legacy algorithm logs a warning that names it. A narrowed list can also name any of these directly.

Why each is acceptable as an opt-in, and why it stays opt-in:

- **Finite-field Diffie-Hellman.** The groups are 2048 and 4096 bits, which RFC 9142 still allows. `group14-sha1` puts SHA-1 in the exchange hash; a collision attack on it would need work before the session against values both sides randomise, so it isn't a real-time attack, but RFC 9142 grades it SHOULD NOT. The peer's value must satisfy 1 < f < p - 1 and be no wider than the group, or the exchange fails before any work is spent on it. The private exponent comes from `RandomNumberGenerator`, at OpenSSH's size: twice the bits of the largest key the session derives, at least 512 bits. The exponentiation is this library's own: Montgomery multiplication on fixed-width limbs with a fixed 4-bit window, every table entry read on every step, no branch or index on the exponent, and every buffer pinned and zeroed afterwards. `BigInteger` isn't used for secrets, because it can't be zeroed and `ModPow` isn't constant-time. No external review has checked that code yet, and its timing hasn't been measured.
- **Its cost.** One handshake does two modular exponentiations: about 9 ms each for group 14 and 17 to 29 ms for group 16, measured on the development machine (x64, Release), a little faster than `BigInteger.ModPow`. A client can make a server spend that before logging in, so **a server offers Diffie-Hellman only when its `KeyExchange` list names it explicitly**, as OpenSSH 10's sshd does. `LegacyUnsafe` on a server adds `ssh-rsa` and the SHA-1 MACs, but no Diffie-Hellman.
- **`ssh-rsa`.** SHA-1 chosen-prefix collisions are practical (Shambles, 2020), and they threaten long-lived signed data. A key exchange signature covers a hash of fresh values from both sides, so a precomputed collision doesn't help against it. The library accepts or makes a SHA-1 signature only where `ssh-rsa` was negotiated from a list that names it. Certificates signed by their CA with SHA-1 are refused whatever the lists say. Without `server-sig-algs`, a client with `ssh-rsa` allowed signs RSA user keys with it, as OpenSSH does; otherwise it uses `rsa-sha2-512`. Platforms whose crypto policy forbids SHA-1 signatures (RHEL 9 and later by default) refuse it, and that becomes `SshNegotiationException` saying so.
- **HMAC-SHA-1.** HMAC doesn't depend on SHA-1's collision resistance, and there is no practical forgery. It's opt-in because policies forbid SHA-1.

Trimming and Native AOT leave the finite-field code out of an application that never uses `LegacyUnsafe` and never sets `SshAlgorithms.KeyExchange` (checked with a trimmed publish: none of the finite-field types are left). The SHA-1 MAC and signature paths are a few lines in shared classes and stay.

BouncyCastle provides Ed25519, X25519, ML-KEM, sntrup761 and Poly1305 (for ChaCha20-Poly1305) where the .NET libraries don't. The ChaCha20 cipher itself is Zorg.Ssh's own code, which has no secret-dependent branch or index, and whose key words are zeroed on dispose. Its working state lives in registers and stack slots, which managed code can't zero. Neither BouncyCastle's code nor ours has been reviewed as part of this project. See [dependencies.md](dependencies.md).

## Out of scope

Not implemented in this version:

- **SCP**, and it won't be added. It's a shell-command protocol with a history of path injection. Use SFTP.
- **Compression**, which is left out of version 1. OpenSSH 10.6 disabled LZ77 in compression because of a side channel.
- Remote forwarding on the server: it refuses every `tcpip-forward` request.
- Agent forwarding. Logging in through a local ssh-agent is supported.
- User certificates on the server: it refuses them. The client can log in with one, and trusts host certificates through `@cert-authority` lines.
- Following `ProxyJump` or `ProxyCommand` from a config file. `SshClientOptions.FromConfig` reads a subset of `~/.ssh/config` and refuses such a host. Use `SshClientOptions.JumpHost` instead.
- `Match` blocks in a config file. They are never evaluated, and `FromConfig` throws when one that could apply sets a keyword that decides trust. `RevokedHostKeys`, `KnownHostsCommand` and `HostKeyAlias` also make it throw. `IdentityAgent` (except `none`), `CertificateFile`, `HostKeyAlgorithms` and `CASignatureAlgorithms` are ignored with a warning. [client.md](client.md#the-agent-certificates-and-sshconfig) has the table.
- X11 forwarding, GSSAPI, host-based login, security keys (`sk-`), PKCS#11 and ML-DSA signatures.
- Older legacy algorithms than those in `LegacyUnsafe` (group1, group exchange, DSA, 3DES, CBC, arcfour, MD5). Equipment that needs only those won't connect.
- Keyboard-interactive login and password changes on the server side.
- Changing an expired password from the client: it fails with `SshAuthenticationException`.
- SFTP versions other than 3.

The agent, host and user certificates for login, and a subset of `ssh_config` exist, with the limits above. Nothing else here is a promise of a date.

## Unverified

What the tests do cover: the interop tests run against OpenSSH 10.x, OpenSSH 7.4 and Dropbear for login and exec, AsyncSSH and Paramiko servers for exec, and OpenSSH 10.x and 7.4 for SFTP. Real OpenSSH clients run against the server for login, exec, every default key exchange and every cipher.

What hasn't been checked:

- **No external security review** of any part, including the transport and the server. There has been no penetration test or audit.
- **Fuzzing is shallow.** Besides the hand-written hostile-input tests, a seeded fuzzer attacks the decoders that read bytes or text from a peer, a file or a local client (the packet reader, `KEXINIT`, public keys and certificates, key files, `known_hosts`, `ssh_config`, the SFTP readers and server dispatch, SOCKS, the agent replies and public key requests). It checks for a wrong exception type, a hang and a large allocation, and a normal test pass runs a short fixed-seed round of it. It isn't coverage-guided, each target has had minutes of runs rather than days, and it can't see a stack overflow or an allocation made on another thread. Eight more targets (the stateful ones) run a whole encrypted in-memory connection against a scripted peer that knows the session keys, so their messages reach the message policy, auth, the connection and channel code and SFTP, on both roles. They check for a wrong exception type (including the library's own catch-all hiding one), a hang after the peer vanishes, limits held on a live connection, a handler that runs before login, a secret in a log or exception, and a task that faulted unobserved. The rekey targets inject messages into the middle of the peer's key exchange (through a test hook that queues past the parking rule) and make the SUT start rekeys, and they check that a forbidden message sent there is refused and never answered. What they can't see: the initial key exchange (it runs before any fuzzed step), the exact point of an injection relative to the SUT's own `KEXINIT` and `NEWKEYS`, a rekey the SUT starts by itself from its byte, packet or time limits, the ssh-agent client, real sockets and the listening loop, and anything that depends on real time (idle and keepalive timeouts), because no clock is faked. They have had minutes of runs, not days, and every finding they made so far was in the connection and channel bookkeeping, which suggests more is left. `CONTRIBUTING.md` says how to run and replay both kinds.
- **Timing side channels** haven't been measured, in this code or in BouncyCastle.
- **Zeroing** is done in code, but nothing proves that no copy remains, and a garbage collector can move memory.
- **The server against scanners.** `ssh-audit` reports no failures, and tests check that. Terrapin-Scanner v1.1.3 is run against it too, in a container, and must report strict key exchange and not vulnerable.
- **SFTP against other servers.** Only OpenSSH's `sftp-server` has been tested. Commercial and appliance servers haven't, and neither has the OpenSSH server for Windows.
- **Real network equipment**, and its quirks.
- **Native AOT** is covered by a smoke test of the algorithms and one in-memory session (a command, an SFTP round trip, the agent protocol and `ssh_config` parsing), not by a real network connection.
- **File types and the Windows agent pipe.** Telling a regular file from a FIFO or device uses `statx` on Linux (tested in the Linux container) and `stat` on macOS (`stat$INODE64` on x64, plain `stat` on Arm, with the mode read at offset 4 from the Darwin 64-bit-inode layout; it was written from the headers and never run, so its answer is checked against `File.Exists` and `Directory.Exists` and a disagreement throws `SshException`). **Known limit:** on any other Unix, such as FreeBSD, and on macOS if those calls are missing, only directories and `/dev/` paths are told apart, so a FIFO elsewhere (for example `/tmp/fifo`) named as a known_hosts, config, `Include` or key file is opened and blocks until a writer appears. A device outside `/dev/` is read up to the size limit. Reads are always size-limited. The check of who serves the Windows agent pipe was tested against the current user's process and with made-up identities, not against another account's pipe or a stopped or non-default agent service.
- **Other platforms.** Day-to-day work happens on Windows x64, with peers in Linux containers. The unit and interop suites also run in a Linux container (`scripts/test-linux.sh`) on Alpine (musl) and Ubuntu (glibc), on x64 only. The CI workflow also targets Ubuntu, but hasn't run yet. macOS and Arm haven't been tried.
- **Long-running connections.** Rekeying has been tested, but not connections left up for days.
- **The public API** can still change before 1.0.
