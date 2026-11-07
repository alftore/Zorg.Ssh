# Dependencies

Every third-party package is reviewed for licence and for future risk before it's added: a package can change licence, add fees, or lose its maintainer. Add a row here in the same change as the package.

Rules:

- A runtime dependency binds everyone who uses Zorg.Ssh, so the bar is high. It needs a permissive licence, and a realistic way to replace it.
- No package with a fee, a commercial tier gating needed features, or a licence declaration step, even in tests.
- Anything shipped stays behind internal types, so it can be swapped without a breaking change.
- Check the licence in the `.nuspec` of the exact version. Don't rely on memory.

## Runtime

| Package | Licence | Why | Future risk | Exit plan |
|---|---|---|---|---|
| BouncyCastle.Cryptography 2.7.0 | MIT | Ed25519, X25519, ML-KEM and sntrup761 on platforms the BCL doesn't cover, and Poly1305 for `chacha20-poly1305@openssh.com`. The ChaCha20 half is our own vectorised code (`ChaCha20Simd`), tested against BouncyCastle's engine and fuzzed against it | Low. Long-lived project under a charity, and permissive since the start. No dependencies of its own. Not marked AOT-compatible, so the AOT smoke test covers it. | Used only behind `Crypto/`. Moves to the BCL family by family as support grows. |
| Microsoft.Extensions.Logging.Abstractions 10.0.14 | MIT | `ILogger`, the standard logging seam | Low. Part of .NET. | Small surface. Could be replaced by our own callback. |

## Build only (not shipped)

| Package | Licence | Why | Risk |
|---|---|---|---|
| Microsoft.CodeAnalysis.PublicApiAnalyzers 5.6.0 | MIT | Tracks the public API | Low. Removing it changes nothing at run time. |

## Tests and benchmarks (not shipped)

| Package | Licence | Why | Risk |
|---|---|---|---|
| xunit.v3 4.0.2 | Apache-2.0 | Test framework | Low. |
| coverlet.MTP 10.1.0 | MIT | Coverage | Low. |
| BenchmarkDotNet 0.15.8 | MIT | Benchmarks | Low. |
| SSH.NET 2026.0.0 | MIT | Benchmark only: a library to compare with in `docs/benchmarks.md` | Low. Only `benchmarks/` references it, so removing it loses a comparison and nothing else. |
| Tmds.Ssh 0.26.0 | MIT | Benchmark only: a library to compare with in `docs/benchmarks.md` | Low. Only `benchmarks/` references it. It depends on the public API analyzers, so that project turns off their rules. |

## Fuzzing (not shipped)

Only `tests/Zorg.Ssh.Fuzz` references SharpFuzz. `src/Zorg.Ssh` gains no dependency, only an `InternalsVisibleTo`. Licences were read from the `.nuspec` of each exact version.

| Package | Licence | Why | Risk |
|---|---|---|---|
| SharpFuzz 2.3.0 | MIT | Coverage feedback for libFuzzer: the target calls `Fuzzer.LibFuzzer.Run`, and the instrumenter patches `Zorg.Ssh.dll` | Low. One maintainer, but small, and the licence has been MIT since the start. Removing it loses fuzzing and nothing else. |
| SharpFuzz.Common 2.2.0 | MIT | Dependency of SharpFuzz | Low. Same project. |
| dnlib 4.4.0 | MIT | IL rewriting inside SharpFuzz. It brings `System.Reflection.Emit` 4.7.0 (MIT, Microsoft) and `System.Reflection.Emit.Lightweight` 4.7.0 for netstandard2.0 only, which net10.0 doesn't pull in. | Low. Widely used, and only the fuzz project loads it. |
| SharpFuzz.CommandLine 2.3.0 | MIT | The `sharpfuzz` instrumenter, a dotnet tool installed in the fuzz image (`scripts/linux/Dockerfile.fuzz`), not a project reference | Low. Same project. |
| libfuzzer-dotnet, commit bd39d4e | MIT | The libFuzzer driver that talks to the .NET process. Built from source in the fuzz image, and the file's SHA-256 is checked before it is compiled. | Low. A single 267-line C++ file. If the repository vanishes, copy the file into `scripts/linux/`. |
| libclang-rt-18-dev (Ubuntu apt) | Apache-2.0 with LLVM exceptions | The libFuzzer runtime for `clang -fsanitize=fuzzer` | Low. In the image only. |

## Test tools built in a container (not shipped)

| Tool | Licence | Why | Risk |
|---|---|---|---|
| Terrapin-Scanner v1.1.3 (commit 5947c1a, RUB-NDS) | Apache-2.0, from its `LICENSE` and the GitHub licence API | One test in `TerrapinScannerTests` runs it against the server. `Peers/terrapin-scanner/Dockerfile` clones the tag, fails unless HEAD is that commit, and builds it in the image. Go modules are checked against its `go.sum`. | Low. Nothing is built or run on the host, and removing it loses one test. |

## Considered and rejected

| Package | Reason |
|---|---|
| Microsoft.Testing.Extensions.CodeCoverage 18.12.0 | Zorg.Json uses it, but it's under proprietary Microsoft terms that limit use to designing, developing and testing, not an open licence. `coverlet.MTP` does the same job under MIT. |
| Testcontainers 4.16.0 | MIT and it worked on Podman, but it adds 12 packages for what a small direct harness does (spike S3). The harness also binds to loopback only. |
| FluentAssertions, Moq, Verify | Licence changes or a licence declaration step in recent versions. Plain xunit assertions are enough. |
