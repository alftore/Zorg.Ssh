# .NET versions

Zorg.Ssh targets the oldest .NET version that's still supported and long-term (LTS). A newer target is added only when it brings something the library uses. This page records what each version means for the library, so the decision can be made again at each release.

| Version | Kind | Released | Support ends | Zorg.Ssh |
|---|---|---|---|---|
| .NET 10 | LTS | November 2025 | November 2028 | The target |
| .NET 11 | STS | November 2026 | November 2028 | Tested in CI, not targeted |
| .NET 12 | LTS | November 2027 (expected) | November 2030 (expected) | Revisit then |

## .NET 10

The current target.

- **Built-in crypto used:** AES-GCM, AES (CTR mode is built on it here, since .NET has none), HMAC, SHA-2, RSA, ECDSA on P-256, P-384 and P-521, and ML-KEM where `MLKem.IsSupported` (OpenSSL 3.5 or later; not on Windows 11 23H2).
- **Not built in, so BouncyCastle provides it:** Ed25519, X25519, Poly1305, sntrup761, and ML-KEM where the platform lacks it. The ChaCha20 half of `chacha20-poly1305@openssh.com` is this library's own code, because .NET only has ChaCha20 combined with Poly1305 in the RFC 8439 form, which OpenSSH doesn't use.
- **Performance:** the per-packet async methods use `PoolingAsyncValueTaskMethodBuilder`.

## .NET 11

Tested: CI runs the `net10.0` tests on the .NET 11 runtime as a required check. No `net11.0` build, because the one useful addition is small and .NET 11 isn't supported for any longer than .NET 10.

- **`X25519DiffieHellman`:** built-in X25519. It passes the RFC 7748 vectors, matches BouncyCastle, and refuses low-order points by itself (it throws `CryptographicException` rather than return an all-zero secret). It's supported on Windows 11 and on Linux with OpenSSL 3.0 and 3.5; macOS and Windows 10 weren't tested. The private key stays in a native handle. It's faster than BouncyCastle on Linux and about four times slower on Windows. It needs a `net11.0` or later build; `Microsoft.Bcl.Cryptography` doesn't bring it to .NET 10. When adopted: use it where `IsSupported` and keep BouncyCastle otherwise, as `MlKem768` does, check the length first, and map `CryptographicException` to `SshProtocolException`.
- **Runtime async (preview):** not worth turning on. Times stay level and allocations rise 4 to 7 times, because the pooled builders stop pooling. Revisit when it leaves preview, by removing the `[AsyncMethodBuilder]` attributes and measuring again.
- **Loopback stalls on Windows:** short round trips between a client and server in the same process stall for 10 to 25 ms more often on .NET 11 than on .NET 10. The stall is in Windows loopback TCP, not .NET; .NET 11's thread pool timing only makes it more frequent. See [Known issues](troubleshooting.md#occasional-10-to-25-ms-delays-over-loopback-on-windows).
- **Smaller additions:** `SafeFileHandle.Type` could replace part of the SFTP server's own file-type check on Linux and macOS. `RandomAccess` now reads and writes pipes. The new `Process` APIs could simplify the test helpers.
- **A `net11.0` build would raise these warnings,** which fail the build: NU1510 (the logging abstractions are part of the framework), CA1307, CA1830 and CA2027.
- **Not relevant:** AES key wrap, HPKE, composite ML-KEM (a different construction from SSH's hybrid), ML-KEM in CMS, Zstandard, and the new x86-64-v2 hardware baseline.
- **Still missing:** Ed25519, raw ChaCha20 and Poly1305, sntrup761.

## .NET 12

Check when it ships:

- Is Ed25519 (EdDSA) built in? That would remove BouncyCastle's largest remaining use.
- Have raw ChaCha20 or Poly1305 been added?
- Has runtime async left preview, and is it faster without the pooled builders?
- Do loopback round trips on Windows still stall more often than on .NET 10?
- Does `X25519DiffieHellman` support macOS?
- Then: target `net12.0` alone once .NET 10 support ends in November 2028, or `net10.0` and `net12.0` together before that if a feature is worth two builds.
