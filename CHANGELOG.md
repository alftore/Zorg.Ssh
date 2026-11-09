# Changelog

All notable changes to Zorg.Ssh are listed here, newest first. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions before 1.0 can break the API in any release, and each break is marked **Breaking**.

## Unreleased

No changes to the library yet. Documentation and repository changes:

- The README and the docs index say what the library has and hasn't had checked: internal and AI-agent reviews, fuzzing and interop tests, and no external security audit. The server is still not for the public internet or for users you don't trust.
- Added this changelog, a security policy with supported versions and response times, issue forms, and a release workflow that publishes with NuGet trusted publishing and a provenance attestation.

## 0.1.0-preview.3 (2026-11-08)

The first version on nuget.org, uploaded by hand from commit `e1ec2ff`. It includes fixes for every finding of an internal pre-audit by a separate AI model.

### Added

- `SshClient.HostKey`: the host key the policy accepted.
- `SshClient.ConnectionClosed` and `WaitForCloseAsync`, to learn when and why a connection ended.
- `SftpTransferOptions.Progress`, for transfer progress.
- `SshServer.Create`, for a server that serves your own streams and never listens.
- `SftpException.IsLocalLimit`, to tell a refusal by the library from the server's answer.
- `SshAlgorithms.UserKeys`: the signature algorithms for user keys, kept apart from `HostKeys`, as OpenSSH keeps `PubkeyAcceptedAlgorithms`.

### Changed

- Host certificate principals are compared exactly, as OpenSSH does. A principal such as `*` used to match as a pattern.
- With a `known_hosts` policy, the client offers the host key types already recorded for the host first, so a server with several key types isn't refused as changed.
- A server accepts only the user key signature algorithms `UserKeys` names, and lists those in `server-sig-algs`. It used to accept any it supported. The client signs only with algorithms `UserKeys` names.
- `SshServerOptions.RequiredAuthMethods` is checked when the server is made.
- A channel's request queue is bounded by bytes, not by 16 requests, so a burst of `env` requests from OpenSSH no longer ends the connection.
- Pre-login Diffie-Hellman work is bounded across the whole server, for a server that offers it.
- The server backs off when accepting connections keeps failing.
- Connection-layer protocol errors are sent to the peer as `PROTOCOL_ERROR`.
- The identification line accepts non-ASCII bytes in its comments field.
- Fewer allocations in the SFTP client and on the receive path.

### Fixed

- Every copy of a password or keyboard-interactive answer the client sends is zeroed.
- `~/` paths are refused when the home directory is empty, instead of becoming relative to the working directory.
- User names from the client are cleaned in the descriptions of the server's request types.
- Data held by a disposed channel stream returns its window.
- Disposing a connection ends it even when its receive loop is stuck in a stream that ignores cancellation.
- A close during a key exchange sends `DISCONNECT` and doesn't wait for the grace period.
- `exit-status` and `exit-signal` count only on a session this side opened.
- SFTP server: a symbolic link is listed as itself, never with its target's permissions; names that aren't UTF-8 are listed on Linux as their bytes; a FIFO is refused before it's opened; `APPEND` writes are atomic on Linux; `statvfs` of a missing path answers `NoSuchFile`; `posix-rename` replaces an empty directory; `OPENDIR` on a directory it can't open is refused.
- SFTP client: a copy without overwrite checks its destination first.
- EC key files that spell out a NIST curve, as macOS writes them, can be read.
- Unit tests pass on macOS arm64.

## 0.1.0-preview.2 (2026-11-07)

Packed, not published to nuget.org.

### Added

- `SftpEntry.HasValidName`, which marks names that aren't valid UTF-8. Paths with unpaired surrogates are refused.
- `SftpClient.CreateDirectoryAsync` with `recursive`.
- The SFTP server reports FIFOs, sockets and devices with their real type on Linux.
- `docs/server.md` says where the SFTP server's answers differ from OpenSSH's.

### Fixed

- The SFTP server sends a Windows name with an unpaired surrogate as bytes, instead of failing.

## 0.1.0-preview.1 (2026-11-07)

Packed, not published to nuget.org. The first preview.

- SSH client: password, public key (also through ssh-agent, and with user certificates) and keyboard-interactive login, `known_hosts` with revoked keys and host certificates, pinned host keys, a subset of `ssh_config`, jump hosts, port forwarding, commands, processes and shells.
- SFTP version 3 client with pipelined transfers, file streams, listings and safe recursive download.
- SSH server with password and public key login, your own session handlers, and an SFTP server rooted at a directory.
- Current algorithms, including ML-KEM and sntrup761 hybrid key exchange and strict key exchange, and `SshAlgorithms.LegacyUnsafe` for old equipment.
- Native AOT and trimming.
