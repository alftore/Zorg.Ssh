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
| BouncyCastle.Cryptography 2.7.0 | MIT | Ed25519, X25519, ML-KEM and sntrup761 on platforms the BCL doesn't cover, and ChaCha20-Poly1305 in OpenSSH's layout | Low. Long-lived project under a charity, and permissive since the start. No dependencies of its own. Not marked AOT-compatible, so the AOT smoke test covers it. | Used only behind `Crypto/`. Moves to the BCL family by family as support grows. |
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

## Considered and rejected

| Package | Reason |
|---|---|
| Microsoft.Testing.Extensions.CodeCoverage 18.12.0 | Zorg.Json uses it, but it's under proprietary Microsoft terms that limit use to designing, developing and testing, not an open licence. `coverlet.MTP` does the same job under MIT. |
| FluentAssertions, Moq, Verify | Licence changes or a licence declaration step in recent versions. Plain xunit assertions are enough. |
