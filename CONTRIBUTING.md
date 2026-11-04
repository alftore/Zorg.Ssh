# Contributing

## Build and test

You need the .NET SDK version in `global.json`.

```
dotnet build Zorg.Ssh.slnx
dotnet test --solution Zorg.Ssh.slnx
```

The build treats warnings as errors, so it has to finish with 0 warnings.

## AOT smoke test

`samples/Zorg.Ssh.AotSmoke` is the Native AOT gate. BouncyCastle isn't marked AOT-compatible, so `VerifyReferenceAotCompatibility` is off and this sample takes its place: it's published with Native AOT and run, and it exercises every algorithm. Trimming keeps only what's used, so add each new algorithm to it. To run it yourself:

```
dotnet publish samples/Zorg.Ssh.AotSmoke -r win-x64 -c Release
samples/Zorg.Ssh.AotSmoke/bin/Release/net10.0/win-x64/publish/Zorg.Ssh.AotSmoke.exe
```

Use `linux-x64` and drop `.exe` on Linux. Windows needs the Visual Studio C++ workload, with `C:\Program Files (x86)\Microsoft Visual Studio\Installer` on `PATH` for vswhere. Ubuntu needs `clang` and `zlib1g-dev`.

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
