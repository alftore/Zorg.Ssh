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

`tests/Zorg.Ssh.Tests/Fuzzing` attacks every decoder that reads bytes or text from a peer, a file or a local client: `SshReader`, `KexInitMessage.Parse`, `SshCertificate.ParseAny`, `OpenSshKeyFormat.Parse`, `SshKeyFile.Load`, `KnownHostsFile.Parse`, `SshConfig.Parse`, the SFTP response readers, `SocksHandshake`, `PacketReader`, the agent replies, `SftpServerSession.DispatchAsync` and `ServerAuthenticator.ParsePublicKey`. Seeds come from the keys, certificates and builders the other tests use. The mutator changes them with bit flips, truncation, splices and boundary values, and it knows where the length fields are, because a wrong length is what a parser has most to get right.

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

## Coverage-guided fuzzing

`tests/Zorg.Ssh.Fuzz` holds three libFuzzer targets for the wire decoders: `packet-reader` (identification line and packet framing), `kex-init` and `sftp-response`. SharpFuzz instruments `Zorg.Ssh.dll` in a container (Ubuntu, glibc), so nothing is installed on your machine.

```
scripts/fuzz.sh kex-init 300      # target, then seconds (default 60)
```

The corpus and any crash inputs stay in the volume `zorg-ssh-fuzz`, so the next run starts where the last stopped. A crash prints its bytes, and the run fails. The only exception a target swallows is `SshException`, as guarantee 3 says. Seed inputs come from `Zorg.Ssh.Fuzz --seed`. Instrumented code faults outside libFuzzer, so don't run an instrumented `Zorg.Ssh.dll` by hand.

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
- **New packages** go through the review in `docs/dependencies.md`.
- **Legacy algorithms** live behind `SshAlgorithms.LegacyInsecure`, and weak-crypto analyzer suppressions stay in those files, with a reason.

## Commits

Signed, with no co-author or generator lines. The README covers how the library is built.
