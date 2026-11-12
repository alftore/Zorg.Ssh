# Security

**Zorg.Ssh has had internal reviews only, not an external security audit.** AI agents helped write it and review it, and no outside party has checked it. This page says what has been tested and what hasn't, so you can judge whether it fits what you need to protect. **Don't put the server on the public internet, or in front of users you don't trust:** see [server.md](server.md#where-to-run-it). To report a problem, follow [SECURITY.md](../SECURITY.md).

## The four guarantees

These are the rules the library is built around. Each has tests, and a change that weakens one needs a design decision. They're goals backed by tests, not proofs.

1. **No message is acted on in a state that doesn't allow it.** One table, `Transport/MessagePolicy`, decides which message may arrive when. The default is deny. A connection message before login ends the connection.
2. **Nothing proceeds on an unverified host key or unauthenticated user.** There's no default host key policy. Anything that weakens a check has `Unsafe` in its name: `HostKeyPolicy.AcceptAnyUnsafe`, `HostKeyPolicy.KnownHostsFileAcceptNewUnsafe` (trust on first use), the `acceptNewHostKeysUnsafe` argument of `SshClientOptions.FromConfig` (which `StrictHostKeyChecking accept-new` needs), and `SshAlgorithms.LegacyUnsafe`, the only way to reach a legacy algorithm. On the server, a public key handler's answer counts only once the client's signature has been verified.
3. **A hostile peer can't cause unbounded memory, a hang or an unhandled exception type.** Buffers, queues and counts have limits, and waits can be cancelled. Failures a peer causes reach you as `SshException` or a derived type.
4. **Secrets never reach logs or exception messages, and are zeroed after use.** See the limits on this under [Secrets](#secrets).

Published SSH advisories in other implementations each have a named regression test, or a reason here why they can't apply. See [Published advisories](#published-advisories).

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

Host keys and public key signatures, the default of both `HostKeys` and `UserKeys`:

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

It's for network equipment, BMCs and old servers that have nothing better, such as HPE iLO 4 and 5, classic Cisco IOS, older Dropbear and RHEL 6. A peer that has anything better still gets it: the legacy names come last, and each side's `KEXINIT` is in the signed exchange hash, so a man in the middle can't strip the modern names. Choosing a legacy algorithm logs a warning that names it.

The legacy names are accepted only on `LegacyUnsafe` and on copies made from it with `with`, so the word `Unsafe` is always in the code that turns one on. A plain `new SshAlgorithms { HostKeys = ["ssh-rsa"] }` throws `ArgumentException`, and the message points at `LegacyUnsafe`. To narrow or reorder the preset, copy it:

```csharp
SshAlgorithms algorithms = SshAlgorithms.LegacyUnsafe with { KeyExchange = ["curve25519-sha256", "diffie-hellman-group14-sha256"] };
```

Why each is acceptable as an opt-in, and why it stays opt-in:

- **Finite-field Diffie-Hellman.** The groups are 2048 and 4096 bits, which RFC 9142 still allows. `group14-sha1` puts SHA-1 in the exchange hash; a collision attack on it would need work before the session against values both sides randomise, so it isn't a real-time attack, but RFC 9142 grades it SHOULD NOT. The peer's value must satisfy 1 < f < p - 1 and be no wider than the group, or the exchange fails before any work is spent on it. The private exponent comes from `RandomNumberGenerator`, at OpenSSH's size: twice the bits of the largest key the session derives, at least 512 bits. The exponentiation is this library's own: Montgomery multiplication on fixed-width limbs with a fixed 4-bit window, every table entry read on every step, no branch or index on the exponent, and every buffer pinned and zeroed afterwards. `BigInteger` isn't used for secrets, because it can't be zeroed and `ModPow` isn't constant-time. No external review has checked that code, and its timing hasn't been measured.
- **Its cost.** One handshake does two modular exponentiations: about 9 ms each for group 14 and 17 to 29 ms for group 16, measured on the development machine (x64, Release), a little faster than `BigInteger.ModPow`. A client can make a server spend that before logging in, so **a server offers Diffie-Hellman only when its `KeyExchange` list names it explicitly**, as OpenSSH 10's sshd does. `LegacyUnsafe` on a server adds `ssh-rsa` and the SHA-1 MACs, but no Diffie-Hellman. Once a server does name it, the cost is bounded as a whole: at most the larger of 1 and half the processors of these computations run at once, across every connection and address, before login. `MaxUnauthenticatedConnections` and `MaxUnauthenticatedPerAddress` limit how many connections wait, not the CPU they can use together, so a client from each of many addresses could otherwise keep every core busy. A connection that has to wait keeps its `LoginGraceTime` and is cancelled with the server: when the time runs out it ends with an `SshConnectionException` and never does the work. Elliptic-curve and ML-KEM key agreement costs microseconds and is not counted, and neither are rekeys after login. Every exchange also costs the server one host-key signature, which is not counted either: about 0.3 ms for Ed25519, 1.3 ms for RSA 3072 and 3 ms for RSA 4096 (Debug build, development machine). A client can cause three of them per connection before login (the first exchange and at most two rekeys), so the worst case is bounded by `MaxUnauthenticatedConnections` and `LoginGraceTime`, as in OpenSSH. An Ed25519 host key keeps it at microseconds. The bound is not an option you can set. A server that offers Diffie-Hellman to many clients at once will make them queue, up to the grace time.
- **`ssh-rsa`.** SHA-1 chosen-prefix collisions are practical (Shambles, 2020), and they threaten long-lived signed data. A key exchange signature covers a hash of fresh values from both sides, so a precomputed collision doesn't help against it. The library accepts or makes a SHA-1 signature only where the list for it names `ssh-rsa`: `HostKeys` for host keys and `UserKeys` for user keys. Certificates signed by their CA with SHA-1 are refused whatever the lists say. Without `server-sig-algs`, a client with `ssh-rsa` allowed signs RSA user keys with it, as OpenSSH does; otherwise it uses `rsa-sha2-512`. Platforms whose crypto policy forbids SHA-1 signatures (RHEL 9 and later by default) refuse it, and that becomes `SshNegotiationException` saying so.
- **HMAC-SHA-1.** HMAC doesn't depend on SHA-1's collision resistance, and there is no practical forgery. It's opt-in because policies forbid SHA-1.

Trimming and Native AOT leave the finite-field code out of an application that never uses `LegacyUnsafe` (checked with a trimmed publish: none of the finite-field types are left). The SHA-1 MAC and signature paths are a few lines in shared classes and stay.

BouncyCastle provides Ed25519, X25519, ML-KEM, sntrup761 and Poly1305 (for ChaCha20-Poly1305) where the .NET libraries don't. The ChaCha20 cipher itself is Zorg.Ssh's own code, which has no secret-dependent branch or index, and whose key words are zeroed on dispose. Its working state lives in registers and stack slots, which managed code can't zero. This project hasn't reviewed BouncyCastle's code, and our own code has had internal reviews only. See [dependencies.md](dependencies.md).

## Published advisories

Advisories in other SSH and SFTP implementations, and where this library stands on each. A test named for the advisory is in `tests/Zorg.Ssh.Tests`; search for the advisory id. It means a regression test exists, not that the code has been audited.

| Advisory | What went wrong | Test, or why it can't apply |
|---|---|---|
| Terrapin, CVE-2023-48795 | Packets injected before `KEXINIT` shift the sequence numbers | `HostilePeerTests.Strict_KEX_rejects_a_KEXINIT_that_is_not_the_first_packet` |
| Erlang CVE-2025-46712 | Optional messages passed in a strict initial exchange | `HostilePeerTests.Strict_KEX_rejects_optional_messages_after_KEXINIT` |
| libssh CVE-2025-8277, CVE-2023-1667 | A wrong first-packet guess in a rekey leaked memory or crashed | `HostilePeerTests.A_wrong_guess_drops_one_packet_and_a_second_stray_packet_is_refused`, `TransportFindingsTests.T3_CVE_2023_1667_*` |
| Go CVE-2025-22869 | A stalled key exchange made the writer buffer without limit | `TransportTests.Writers_wait_while_a_rekey_is_stalled_and_nothing_grows` |
| Go CVE-2026-46597 | A padding length wrapped in a byte | `PacketCipherTests.Regression_Go_CVE_2026_46597_*` |
| SSH.NET GHSA-h5q6-2gr6-3g3m | An endless banner line grew memory | `PacketReaderTests.An_endless_line_without_a_line_feed_is_capped` |
| SSH.NET GHSA-vhpg-4g9v-rppq | A channel packet size of 0 made the send loop spin | `ConnectionEndTests.SshNet_GHSA_vhpg_4g9v_rppq_*` |
| libssh2 CVE-2026-55199 | `EXT_INFO` parser looped on a huge count | `TransportFindingsTests.CVE_2026_55199_*` |
| OpenSSH CVE-2025-26466 | `PING` flood before login | `TransportFindingsTests.CVE_2025_26466_*` |
| Erlang CVE-2025-32433 | Channel requests acted on before login | `MessagePolicyTests.Connection_messages_before_auth_end_the_connection`, `PublicServerTests.A_connection_message_before_login_closes_the_connection_and_runs_nothing` |
| AsyncSSH CVE-2023-46445, CVE-2023-46446 | Auth and `EXT_INFO` messages out of order | `MessagePolicyTests.Auth_messages_only_flow_the_right_way_in_the_auth_phase`, `AuthTests.USERAUTH_SUCCESS_before_the_auth_phase_ends_the_connection` |
| Go CVE-2026-39828 | Permissions lost after a partial login | `AuthTests.Every_key_proven_in_a_partial_login_stays_on_the_record` |
| Go CVE-2024-45337 | The last key queried was trusted, not the key proven | `AuthTests.Go_CVE_2024_45337_*` |
| libssh CVE-2023-2283 | Signature check failed open on an error | `SshKeyTests.Libssh_CVE_2023_2283_*`, `AuthTests.Libssh_CVE_2023_2283_*`, `HostilePeerTests.Libssh_CVE_2023_2283_*` |
| libssh CVE-2026-59849 | The client's credential loop never ended | `AuthTests.Libssh_CVE_2026_59849_*` |
| OpenSSH CVE-2026-35414 | A comma in a certificate principal matched a part of it | `HostileCertificateTests.OpenSSH_CVE_2026_35414_*` |
| OpenSSH CVE-2026-35387 | One ECDSA algorithm in a list admitted the other curves | `UserKeyAlgorithmTests.OpenSSH_CVE_2026_35387_*` |
| Go CVE-2026-39830 | Unsolicited global replies blocked the read loop | `HostileForwardingTests.A_flood_of_global_replies_is_dropped_and_cannot_answer_a_later_request` |
| Apache MINA CVE-2021-30129 | Unbounded buffers in SFTP and port forwarding | `HostileForwardingTests.Mina_CVE_2021_30129_*`, `SftpHostileServerTests.Mina_CVE_2021_30129_*`, `ConnectionEndTests.Data_past_the_window_disconnects_with_protocol_error` |
| libssh CVE-2026-59850 | Data delivered on a closed channel | `ConnectionEndTests.Libssh_CVE_2026_59850_*` |
| libssh CVE-2026-59848 | SFTP replies with unknown ids were kept | `SftpHostileServerTests.Libssh_CVE_2026_59848_*` |
| SSH.NET GHSA-q939-rpr3-3284, JSch CVE-2016-5725, OpenSSH CVE-2026-59995 | A recursive download wrote outside the destination from hostile names | `SftpNamesTests.SshNet_2026_*`, which cover SFTP downloads |
| Apache MINA CVE-2023-35887 | A rooted file system showed whether paths outside the root exist | `SftpServerPathTests.Mina_CVE_2023_35887_*` |
| Erlang CVE-2026-23942 | Root checked as a string prefix, so `user1` admitted `user10` | `SftpServerPathTests.Erlang_CVE_2026_23942_*` |
| Erlang CVE-2026-32147 | A handle kept the client's path, so it could act outside the root | `SftpServerPathTests.Erlang_CVE_2026_32147_*` |
| Go CVE-2026-46595 | A certificate `source-address` was not enforced | Can't apply: the server doesn't accept user certificates (`ServerCertificateTests`). A certificate is a failed attempt and the handler never sees it |
| PuTTY CVE-2024-31497 | Biased ECDSA nonces leaked P-521 keys | Can't apply: ECDSA signing is the platform's `ECDsa.SignData`, with a fresh random nonce each time. The library has no nonce code of its own |
| OpenSSH compression advisories | Compression side channel and oversized output | Can't apply: only `none` compression is offered or accepted |
| SSH.NET GHSA-mggc-4xg6-vcxf | An SCP path went into a shell command | Can't apply: there is no SCP |
| libssh CVE-2025-5318, CVE-2025-5449, CVE-2026-15370, CVE-2026-0968, the 2026 `sftp-extensions` advisory; libssh2 CVE-2019-3858, CVE-2019-3860 | C memory errors in SFTP: out-of-bounds reads, length overflow, a stack overflow on a long name, a null dereference | Can't apply as memory errors. In C# the same input could only cause the wrong exception type, which the fuzz targets `SftpParser response readers` and `SftpServerSession.DispatchAsync` check. The client reads the long name and skips it, and `SftpHostileServerTests.Too_many_extensions_are_refused` and `SftpServerProtocolTests.A_handle_of_the_wrong_length_is_refused` cover the extension and handle cases |

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

What has been done: internal reviews by the AI agents that build the library, of each stage and of the trust, forwarding and upper layers; a pre-audit by a separate AI model (Fable) of the transport, auth, connection and SFTP code, whose findings were all fixed, most with a regression test; the hand-written hostile-input tests and the fuzzer described below; and the interop tests. The interop tests run against OpenSSH 10.x, OpenSSH 7.4 and Dropbear for login and exec, AsyncSSH and Paramiko servers for exec, and OpenSSH 10.x and 7.4 for SFTP. Real OpenSSH clients run against the server for login, exec, every default key exchange and every cipher.

What hasn't been checked:

- **No external security review** of any part, including the transport and the server. There has been no penetration test or audit, and none is planned. The pre-audit above was done by an AI model, not by an accountable outside party, so it isn't an audit.
- **Fuzzing is shallow.** Besides the hand-written hostile-input tests, a seeded fuzzer attacks the decoders that read bytes or text from a peer, a file or a local client (the packet reader, `KEXINIT`, public keys and certificates, key files, `known_hosts`, `ssh_config`, the SFTP readers and server dispatch, SOCKS, the agent replies and public key requests). It checks for a wrong exception type, a hang and a large allocation, and a normal test pass runs a short fixed-seed round of it. It isn't coverage-guided, each target has had minutes of runs rather than days, and it can't see a stack overflow or an allocation made on another thread. Eight more targets (the stateful ones) run a whole encrypted in-memory connection against a scripted peer that knows the session keys, so their messages reach the message policy, auth, the connection and channel code and SFTP, on both roles. They check for a wrong exception type (including the library's own catch-all hiding one), a hang after the peer vanishes, limits held on a live connection, a handler that runs before login, a secret in a log or exception, and a task that faulted unobserved. The rekey targets inject messages into the middle of the peer's key exchange (through a test hook that queues past the parking rule) and make the SUT start rekeys, and they check that a forbidden message sent there is refused and never answered. What they can't see: the initial key exchange (it runs before any fuzzed step), the exact point of an injection relative to the SUT's own `KEXINIT` and `NEWKEYS`, a rekey the SUT starts by itself from its byte, packet or time limits, the ssh-agent client, real sockets and the listening loop, and anything that depends on real time (idle and keepalive timeouts), because no clock is faked. They have had minutes of runs, not days, and every finding they made so far was in the connection and channel bookkeeping, which suggests more is left. `CONTRIBUTING.md` says how to run and replay both kinds.
- **Timing side channels** haven't been measured, in this code or in BouncyCastle.
- **Zeroing** is done in code, but nothing proves that no copy remains, and a garbage collector can move memory.
- **The server against scanners.** `ssh-audit` reports no failures, and tests check that. Terrapin-Scanner v1.1.3 is run against it too, in a container, and must report strict key exchange and not vulnerable.
- **SFTP against other servers.** Only OpenSSH's `sftp-server` has been tested. Commercial and appliance servers haven't, and neither has the OpenSSH server for Windows.
- **Real network equipment**, and its quirks.
- **The server on the public internet.** It has never faced one, and it isn't meant to: see [server.md](server.md#where-to-run-it). That stays the advice whatever the version number.
- **Native AOT** is covered by a smoke test of the algorithms and one in-memory session (a command, an SFTP round trip, the agent protocol and `ssh_config` parsing), not by a real network connection.
- **File types and the Windows agent pipe.** Telling a regular file from a FIFO or device uses `statx` on Linux (tested in the Linux container) and `stat` on macOS (`stat$INODE64` on x64, plain `stat` on Arm, with the mode read at offset 4 from the Darwin 64-bit-inode layout, written from the headers. The Arm path runs in CI on macOS arm64. The x64 path has never run. Either answer is checked against `File.Exists` and `Directory.Exists`, and a disagreement throws `SshException`). **Known limit:** on any other Unix, such as FreeBSD, and on macOS if those calls are missing, only directories and `/dev/` paths are told apart, so a FIFO elsewhere (for example `/tmp/fifo`) named as a known_hosts, config, `Include` or key file is opened and blocks until a writer appears. A device outside `/dev/` is read up to the size limit. Reads are always size-limited. The SFTP server lists directories on Linux with `openat`, `getdents64` (musl's `getdents` where musl exports no `getdents64`, as on the Alpine container), `statx` and `readlinkat`, so a name that isn't UTF-8 keeps its bytes. The `open` flags differ by architecture: the values for x64, x86, RISC-V and LoongArch (asm-generic) and for Arm and Arm64 were taken from the kernel headers, but only x64 has run, on glibc and musl. What was opened is checked to be a directory before it's read. The check of who serves the Windows agent pipe was tested against the current user's process and with made-up identities, not against another account's pipe or a stopped or non-default agent service.
- **Other platforms.** Day-to-day work happens on Windows x64, with peers in Linux containers. The unit and interop suites also run in a Linux container (`scripts/test-linux.sh`) on Alpine (musl) and Ubuntu (glibc), on x64 only. CI builds and runs the unit tests on Windows and Ubuntu, the interop suite with Docker peers on Ubuntu, and the Native AOT smoke test, on every push. The unit tests pass on macOS arm64 in CI, in a job started by hand. macOS x64 and Arm Linux haven't been tried.
- **Long-running connections.** Rekeying has been tested, but not connections left up for days.
- **The public API** can still change before 1.0.
