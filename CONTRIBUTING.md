# Contributing

## Build and test

You need the .NET SDK version in `global.json`.

```
dotnet build Zorg.Ssh.slnx
dotnet test --solution Zorg.Ssh.slnx
```

The build treats warnings as errors, so it has to finish with 0 warnings.

## The Linux gate

Most of the OpenSSH tests need `ssh` and `ssh-keygen`, so a plain Linux image skips them. The Linux gate builds and tests in a container that has them. It needs Podman or Docker, and installs nothing on your machine.

```
scripts/test-linux.sh                    # unit tests on Alpine (musl, OpenSSL 3.5, so BCL ML-KEM runs)
scripts/test-linux.sh --variant ubuntu   # unit tests on Ubuntu (glibc, OpenSSL 3.0, so no ML-KEM)
scripts/test-linux.sh --interop          # also the interop suite, with peers started through Podman
scripts/test-linux.sh --aot              # also a Native AOT publish and run in the container
```

The script sends the tree into the container as a tar stream, so uncommitted edits are tested and the Windows checkout is never mounted. NuGet packages are cached in the volume `zorg-ssh-nuget`. Every step has a timeout. Set `ZORG_SSH_CONTAINER_CLI` if Podman or Docker isn't on `PATH`.

The containers use `--network host`. On the Podman machine used for development, the default rootless network ran at about 100 KB/s, which made `apk`, `apt-get` and `dotnet restore` look hung. Don't remove it unless you've measured.

The only skips left should be the platform ones: Windows rules, NTFS streams, named pipes, and "ordinary names elsewhere", plus ML-KEM on the Ubuntu variant.

### Required peers

`ZORG_REQUIRE_PEERS=1` turns every "isn't installed" skip into a failure: no `ssh`, `ssh-keygen`, `sftp` or container engine. `CI=true` does the same. The script sets it, and so does `.github/workflows/ci.yml`. A run that passes by skipping the OpenSSH tests proves nothing, so set it whenever you want a result you can trust. To see it work, run `scripts/test-linux.sh --hide-ssh`: it removes `ssh` from the container, and the run fails.

## Fuzzing

`tests/Zorg.Ssh.Tests/Fuzzing` attacks every decoder that reads bytes or text from a peer, a file or a local client: `SshReader`, `KexInitMessage.Parse`, `SshCertificate.ParseAny`, `OpenSshKeyFormat.Parse`, `SshKeyFile.Load`, `KnownHostsFile.Parse`, `SshConfig.Parse`, the SFTP response readers, `SocksHandshake`, `PacketReader`, the agent replies, `SftpServerSession.DispatchAsync`, `ServerAuthenticator.ParsePublicKey` and the Diffie-Hellman peer value check. Seeds come from the keys, certificates and builders the other tests use. The mutator changes them with bit flips, truncation, splices and boundary values, and it knows where the length fields are, because a wrong length is what a parser has most to get right.

One target isn't a decoder: `ChaCha20Simd against BouncyCastle` runs the library's own ChaCha20 and BouncyCastle's engine on random keys, sequence numbers and data, on every path the machine supports (scalar, 128-bit and 256-bit vectors), in place and not, and fails if one byte differs. `ChaCha20SimdTests` pins the same paths to RFC 8439, to BouncyCastle for every length from 0 to 4096, and to the slow reference for the 64-bit block counter. To see the paths a CPU without AVX2 or SSE would take, run those tests with `DOTNET_EnableAVX2=0`, `DOTNET_EnableSSE41=0`, `DOTNET_EnableSSE3=0` or `DOTNET_EnableHWIntrinsic=0`. `Path.Auto` then picks a narrower path, and the unsupported ones drop out of the test data.

Each input is checked for the three failures guarantee 3 rules out: an exception that isn't the decoder's documented type, a run past a time limit (5 seconds), and a small input that allocates a lot. `FuzzAllowedExceptions` in `FuzzTargets.cs` is the one table of allowed types. Don't add a type there to make a target pass.

```
dotnet test --project tests/Zorg.Ssh.Tests --no-build --filter-class "*FuzzTests"    # the short run, a few seconds, fixed seed
ZORG_FUZZ_MINUTES=2 dotnet test --project tests/Zorg.Ssh.Tests --no-build --filter-class "*FuzzTests"   # a long run
ZORG_FUZZ_SEED=123 ZORG_FUZZ_TARGET="KexInit" dotnet test --project tests/Zorg.Ssh.Tests --no-build --filter-class "*FuzzTests"   # replay
ZORG_FUZZ_MINUTES=2 scripts/test-linux.sh --args "--filter-class *FuzzTests"    # a long run in the Linux container
```

`ZORG_FUZZ_MINUTES` gives every target that long, all at once, and starts from a seed taken from the clock. A summary of each target goes to the console and to `zorg-fuzz-report.txt` in the temp directory (`ZORG_FUZZ_REPORT` names another file). With none of the variables set, the run is short and uses one fixed seed. `ZORG_FUZZ_TARGET` limits a run to targets whose name contains the text, `ZORG_FUZZ_INPUT_SECONDS` changes the time limit, and `ZORG_FUZZ_VERBOSE=1` prints the refusal reasons and the stages reached. Run the test program directly (`tests/Zorg.Ssh.Tests/bin/Debug/net10.0/Zorg.Ssh.Tests -class Zorg.Ssh.Tests.Fuzzing.FuzzTests -showLiveOutput`) to see the console output of a passing run.

A failure prints `target=<name> seed=<number>`, the input in base64, and the line to replay it. One number rebuilds the input, on any machine. After a hang the test process may keep a spinning thread, so run the replay in a fresh process. A stack overflow can't be caught: a long run keeps the seed it was on in `zorg-fuzz-last-seed-<pid>-<target>.bin` in the temp directory, as an 8-byte little-endian number.

The corpus keys are generated at test time, never stored: RSA by BouncyCastle's key generator on a fixed-seed deterministic generator, ECDSA from a hash of a fixed label, Ed25519 from a fixed seed (`Fuzzing/FuzzKeys.cs`). A BouncyCastle upgrade can change the RSA key, which changes the inputs old seeds rebuild; `The_generated_keys_are_the_same_on_every_machine_and_load_in_every_format` pins a hash of the generated text and says when that happens.

Every finding gets a fix in `src` and a named regression test with the input written out in the test, in `Fuzzing/FuzzRegressionTests.cs`. A finding that would weaken a guarantee, or needs a design choice, is recorded instead of fixed here.

To add a target, write a corpus in `FuzzCorpus.cs`, add the target and its row in `FuzzAllowedExceptions` in `FuzzTargets.cs`, and say which stages it reaches with `FuzzNotes.Reached`. The tests insist that most seeds are accepted and that a share of mutated inputs get all the way through, so that a target can't quietly go shallow.

## Stateful fuzzing

The decoder targets can't reach anything that sits behind an encrypted handshake. `tests/Zorg.Ssh.Tests/Fuzzing/Stateful` can. Each of its eight targets runs a real in-memory SSH connection, key exchange and all, against a scripted hostile peer, and checks what comes out. The peer is a `SshTransport` in the other role, so it ran the key exchange itself, knows the session keys, and its fuzzed messages are encrypted and MACed correctly. They get past the transport and into the message policy, the auth code, the connection and channel code and SFTP. Nothing in `src` is weakened for this: the peer sends through the same `SendAsync` every upper layer uses. The only seams are read-only counts of what a connection and a channel hold, and a hook that hands a server its started connection.

| Target | What it attacks |
| --- | --- |
| `Stateful server, before login` | The server's service and userauth handling: password, publickey (queried, signed, wrongly signed), keyboard-interactive, hostbased, `none`, and connection messages sent too early. Its handlers refuse every complete login, so nothing past auth may run. |
| `Stateful server, after login` | Channel opens of every type, channel requests, window adjusts, data, EOF, close, global requests and `tcpip-forward`, on a logged-in server whose handlers really run. |
| `Stateful client, during login` | Fuzzed replies to a client that tries a key, keyboard-interactive and a password: failures, `PK_OK`, prompts, banners, `EXT_INFO`. |
| `Stateful client, after login` | Fuzzed channel and global traffic, including `forwarded-tcpip` opens, against a client application that runs commands, processes, shells, forwards and SFTP. |
| `Stateful SFTP, server side` | The server's SFTP over a live channel, driven by the framed request runs of the SFTP server target. Handles from the server's replies fill later requests. |
| `Stateful SFTP, client side` | A hostile SFTP server answering a real `SftpClient`, through `SftpSession`'s version exchange and read loop. The peer is an honest SFTP server whose next answer a fuzz op can replace, mutate or precede with a stray one. |
| `Stateful server, rekey and order` and `Stateful client, rekey and order` | Rekeys started by the peer or by the SUT between the other messages, messages injected into the middle of the peer's key exchange (see below), key exchange messages after the exchange, and replayed or reordered logins. |

The input of a stateful target is a list of steps (`FuzzOps.cs`): send this payload, send this data on a channel, send this publickey request signed with the real session id, wait for a message, rekey, start an application call. The corpus is valid sequences. The mutator (`SequenceMutator.cs`) changes bytes inside a message with the same mutator as the decoder targets, and also reorders, replays, drops, retypes and floods whole messages, or slips in one from another phase. A failure prints the steps in words under the base64.

What each input is checked for:

- **Exceptions.** Only `SshException` types may leave the connection, and none may be the library's catch-all ("This is a bug in Zorg.Ssh") hiding another type. `FuzzAllowedExceptions` has no row for these targets, so any other exception is a finding. Logged exceptions are judged the same way.
- **Hangs.** The peer vanishes, and then `ServeStreamAsync`, the connect call, every application call and the dispose must end with no token passed. A send that waits 8 seconds, or a probe message the SUT neither answers nor closes over, is a hang too.
- **Memory.** After the probe, a live connection must hold at most its limits: channels, pending opens, pending global requests, deferred sends, queued requests, and a receive window between zero and its size. `StatefulMemoryTests` also runs thousands of messages on one connection and requires that the live heap doesn't grow.
- **Guarantees 1 and 2.** The server rigs refuse every complete login. A handler that runs, a `USERAUTH_SUCCESS` that goes out, or a message the peer's own policy refuses because the SUT sent it in the wrong phase is reported as `GUARANTEE 1` or `GUARANTEE 2 BREACH`. Stop and tell the maintainer before fixing one.
- **Guarantee 4.** The password and the private key of the setup must not appear in any log entry or exception, and the server must not send the password back.
- **Unobserved tasks.** A task that faulted and was never awaited is reported once it is collected, with the type of the task. The event is process-wide, so this check runs only in a fuzz run (`ZORG_FUZZ_MINUTES` or `ZORG_FUZZ_TARGET` set): in a normal pass it would blame these targets for tasks that tests running beside them leave behind.

```
ZORG_FUZZ_TARGET="Stateful" dotnet test --project tests/Zorg.Ssh.Tests --no-build --filter-class "*FuzzTests"      # only these targets, the short run
ZORG_FUZZ_MINUTES=5 ZORG_FUZZ_TARGET="Stateful" dotnet test --project tests/Zorg.Ssh.Tests --no-build --filter-class "*FuzzTests"   # a long run
ZORG_FUZZ_SEED=123 ZORG_FUZZ_TARGET="Stateful client, after login" dotnet test --project tests/Zorg.Ssh.Tests --no-build --filter-class "*FuzzTests"   # replay
```

A normal pass adds about six seconds. A handshake takes 2 to 3 ms, and a whole input 5 to 40 ms, so with all eight targets running at once a target does 7 to 30 inputs a second (about 40,000 inputs in five minutes for all eight). Waits for a message the SUT should send are short (60 ms, 250 ms in a long run), because the cause is gone when a mutation removed it. Run a replay in a fresh process: a connection that hung is abandoned, and the application calls are racing a peer, so a replay of the same seed can differ by the timing of the SUT's answers. The seed rebuilds the input exactly.

Key exchange injection. `SshTransport.SendIgnoringKexForTests` queues a message past the parking rule, so the peer can break it. The rekey targets use it three ways (`KexInject`, `KexCanary` and `SutRekey` in `FuzzOps.cs`). `KexInject` sends a fuzzed payload (connection, auth, channel data, IGNORE, DEBUG, KEX messages) in the middle of the peer's own key exchange, after a chosen number of yields, so the injection point moves through the exchange. `KexCanary` starts a peer rekey and queues a channel open right behind the peer's `KEXINIT`, where policy forbids it. The SUT must end the connection and must not answer: a confirmation or refusal that names the canary's channel, or a connection still open 8 seconds later, is reported as `GUARANTEE 1 BREACH`, and the tests pin it with fixed inputs. `SutRekey` makes the SUT start the rekey (`RequestRekey` on its transport), so the peer is the answering side and the SUT's own traffic parks while it waits. The report counts each path as a stage (`kex: ...`).

What it can't see. The initial key exchange: the peer's handshake runs inside `SshTransport.StartAsync` before any op, so nothing can be injected into it. Injections land between the peer's `KEXINIT` and `NEWKEYS` but their exact position is only steered by yields, not tied to the SUT's own `KEXINIT` or to the moment before `NEWKEYS`, because those messages are consumed inside the transport. The canary is the only injection with a verdict of its own; for the others the general oracles judge. The SUT starts a rekey only when an op asks (the rig does not lower `RekeyBytes` or `RekeyPackets`), and only after login. The ssh-agent client code, and anything that needs a real socket (`SshClient.ConnectAsync`, jump hosts, the listening loop), isn't reached. Time is real: no `TimeProvider` is faked, so idle and keepalive timeouts aren't exercised.

To add a stateful target, write valid sequences in `StatefulTargets.cs`, add the target to `Build`, and say what counts as deep with a `Depth`. The tests insist that most seeds reach it.

## Coverage-guided fuzzing

`tests/Zorg.Ssh.Fuzz` holds four libFuzzer targets for the wire decoders: `packet-reader` (identification line and packet framing), `packet-reader-ctr-eam` (framing through AES-CTR with encrypt-and-MAC, where the length is encrypted), `kex-init` and `sftp-response`. SharpFuzz instruments `Zorg.Ssh.dll` in a container (Ubuntu, glibc), so nothing is installed on your machine.

```
scripts/fuzz.sh kex-init 300      # target, then seconds (default 60)
```

The corpus and any crash inputs stay in the volume `zorg-ssh-fuzz`, so the next run starts where the last stopped. A crash prints its bytes, and the run fails. The only exception a target swallows is `SshException`, as guarantee 3 says. Seed inputs come from `Zorg.Ssh.Fuzz --seed`. Instrumented code faults outside libFuzzer, so don't run an instrumented `Zorg.Ssh.dll` by hand.

## Interop time limits

Interop tests wait on containers and on peers that may hang. Every step has its own timeout, and under those there are two backstops (`tests/Zorg.Ssh.InteropTests/InteropLimits.cs`). A test has 5 minutes: write `[InteropFact]` or `[InteropTheory]`, never `[Fact]` or `[Theory]`, and xunit fails the test when the time is up, even if it is blocked on a thread. A class has 20 minutes: the first test that starts after that fails at once with the name of the class, so a class takes at most 25 minutes. `Every_interop_test_has_a_time_limit` fails if a test is declared without the first.

Tests never listen on an address other than loopback, because a Windows Defender Firewall prompt for the test host can't be answered on an unattended machine. Containers that need the server on the host reach it through a relay inside the container (`Peers/python-ssh/relay.py`).

## AOT smoke test

`samples/Zorg.Ssh.AotSmoke` is the Native AOT gate. BouncyCastle isn't marked AOT-compatible, so `VerifyReferenceAotCompatibility` is off and this sample takes its place: it's published with Native AOT and run, and it exercises every algorithm. Trimming keeps only what's used, so add each new algorithm to it. To run it yourself:

```
dotnet publish samples/Zorg.Ssh.AotSmoke -r win-x64 -c Release
samples/Zorg.Ssh.AotSmoke/bin/Release/net10.0/win-x64/publish/Zorg.Ssh.AotSmoke.exe
```

It also opens a real connection: an in-memory client and server, a command, an SFTP round trip, the agent protocol and `ssh_config` parsing. It must publish with no trim or AOT warnings. Use `linux-x64` and drop `.exe` on Linux, or run `scripts/test-linux.sh --aot` for `linux-musl-x64`. Windows needs the Visual Studio C++ workload, with `C:\Program Files (x86)\Microsoft Visual Studio\Installer` on `PATH` for vswhere. Ubuntu needs `clang` and `zlib1g-dev`.

## Conventions

- **XML docs on all public members**, with an `<example>`.
- **`CancellationToken` on every async method.**
- **`Unsafe` in the name** of anything that weakens security.
- **Exceptions say what to do next.** Peer-caused failures are `SshException` types, never `IndexOutOfRangeException` and the like.
- **Public API changes** update `src/Zorg.Ssh/PublicAPI.Unshipped.txt`. The build fails otherwise.
- **BouncyCastle stays internal.** Its types never appear in the public API.
- **Vertical slices.** Tests and docs land in the same commit as the code.
- **Tests listen on loopback only** (`IPAddress.Loopback`, never `Any`), because anything wider prompts the Windows firewall. To test several source addresses, bind the client to 127.0.0.x and connect to 127.0.0.1. `ListenAddressGuardTests` enforces this.
- **New packages** go through the review in `docs/dependencies.md`.
- **Legacy algorithms** live behind `SshAlgorithms.LegacyUnsafe`, and weak-crypto analyzer suppressions stay next to them, with a reason. Their names are in `Crypto/LegacyAlgorithms.cs`, and the finite-field code is reached only through `KeyExchangeExtension`, which only `LegacyUnsafe` and an explicit `KeyExchange` list create, so trimming can drop it. Never add group1, group exchange, `ssh-dss`, 3DES, arcfour, MD5 or CBC.

## Commits

Signed, with no co-author or generator lines. The README covers how the library is built.
