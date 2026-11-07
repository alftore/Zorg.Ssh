# Benchmarks

Zorg.Ssh measured against SSH.NET 2026.0.0 and Tmds.Ssh 0.26.0, talking to a real OpenSSH server. These numbers are from one machine, measured on 7 November 2026 on `fcb9e80`, one full run. The first numbers were measured on 5 November 2026 and are kept in [what changed](#what-changed-since-5-november). Read [the limits](#limits) before you use them for anything.

## Summary

- **Zorg.Ssh isn't faster than the other two overall.** It is ahead in login and level in exec, and behind in AES-GCM download and in ChaCha20 transfers against SSH.NET. Most upload rows are inside the noise.
- **Login: 67 ms, against 71 ms for SSH.NET and 111 ms for Tmds.Ssh.** The gap to SSH.NET (6%) is about one and a half standard deviations, so call it a tie with Zorg.Ssh slightly ahead. Tmds.Ssh is 66% slower. The `--phases` measure gives the same order: 66.6, 69.4 and 111.7 ms.
- **Exec: a tie.** 44.3, 45.0 and 47.7 ms, and most of that is the server.
- **AES-GCM download: Zorg.Ssh is slowest.** 475 ms against 415 ms for SSH.NET and 390 ms for Tmds.Ssh, so 13% and 18% more time. This is the reverse of 5 November, when all three were level at the speed of the path. The path (270 to 310 MiB/s) isn't the limit for Zorg.Ssh this time, at 269 MiB/s, but the standard deviations (4% to 7%) leave the gap to SSH.NET only about 3 deviations wide, and it moved between runs before.
- **AES-GCM upload:** Zorg.Ssh 454 ms, SSH.NET 531 ms, Tmds.Ssh 606 ms. The standard deviations are 18% to 20%, so only Tmds.Ssh's lag is plausibly real, and it wasn't in the first run (it was 62% then).
- **ChaCha20: SSH.NET is ahead.** Its download took 5% less than Zorg.Ssh's and its upload 12% less, in both cases inside the noise for upload. Tmds.Ssh's download is 2.7 times slower. Its upload is level.
- **Two things changed after that run, both measured against `main` with the trees taking turns.** The AES download "regression" is noise: 422 ms for both trees over eight runs each, so the 476 ms above was a slow moment, and the AES download rows for the other two libraries should be read with that in mind ([the check](#the-aes-download-check)). And ChaCha20 now runs on the library's own vector code, which makes ChaCha20 download 1.23 to 1.29 times as fast (about 504 ms, against about 637 ms) and upload 1.68 times as fast (489 ms, against 823 ms). SSH.NET and Tmds.Ssh weren't measured again, so the ChaCha20 rows in the table below are from before the change ([the numbers](#chacha20-in-vector-code)).
- **Memory: Zorg.Ssh now allocates 10 KB per command**, against 12.7 KB for SSH.NET and 3.1 KB for Tmds.Ssh. In transfers it allocates 9 to 33 times what Tmds.Ssh does. Against SSH.NET it allocates less on download (0.3 to 0.7 times) and more on upload (1.5 to 1.7 times).

## Setup

| | |
|---|---|
| Machine | Intel Core i9-9900K at 3.60 GHz, 8 cores and 16 threads, no SHA-NI, 32 GB RAM |
| Operating system | Windows 11 23H2 (10.0.22631) |
| Runtime | .NET 10.0.14, SDK 10.0.403, RyuJIT x86-64-v3, Release build |
| Tool | BenchmarkDotNet 0.15.8 |
| Zorg.Ssh | 0.1.0-alpha, commit `fcb9e80` |
| SSH.NET | 2026.0.0 |
| Tmds.Ssh | 0.26.0 |
| Server | OpenSSH_10.6p1 with OpenSSL 3.5.7, on Alpine edge |
| Container | Podman 6.1.4 on a WSL 2 machine with 8 CPUs and 2 GiB, Linux 6.18.54 |
| Path | Client on Windows, through a port published on `127.0.0.1`, to the container |
| Machine state | Quiet when it started: total CPU at 0 to 5% over three samples, no test run, no benchmark and no other container jobs. Other tools' idle build servers were running. Nothing was checked during the run, so a short burst of outside work can't be ruled out. |

### Algorithms

Zorg.Ssh has no option to choose algorithms, so the server does the pinning, with `sshd -o`. That applies the same setting to all three clients.

| Family | Value |
|---|---|
| Cipher | `aes256-gcm@openssh.com`, and for SFTP also `chacha20-poly1305@openssh.com` |
| Key exchange | `curve25519-sha256`, and for login also `mlkem768x25519-sha256` |
| Host key | `ssh-ed25519` |
| MAC | None: both ciphers are AEAD |
| Compression | None |

The server also ran with `LogLevel=ERROR`, because the test image logs verbosely, and `PerSourcePenalties=no`, because a run makes many connections from one address.

### Method

- Each library logs in with a password, and accepts any host key. None of the host key handling on a real deployment is measured.
- Each library runs on its defaults, and uses its async API. Nothing was tuned for any of them, including chunk sizes and requests in flight.
- Benchmarks that reach the container use BenchmarkDotNet's Monitoring strategy, with a new process and a new container for each case. Exec and login run 3 warmup and 15 measured iterations. SFTP runs 2 warmup and 8 measured iterations.
- The power plan was left as it was.
- **Exec:** `echo ok` on a connection that's already open, 20 per iteration. Output is checked in the setup.
- **Login:** TCP connect, key exchange, password login and close, 5 per iteration.
- **SFTP:** one 128 MiB file of random bytes, on a session that's already open. The client side is memory: a `MemoryStream` for upload and `Stream.Null` for download. The server side is the container's `/tmp`. The setup first uploads the file, downloads it again, and compares every byte, for each library.
- **Ciphers:** `PacketCipher` in process, with no network. `Seal` is one packet sent. `SealThenOpen` is one packet sent and received.

To reproduce it:

```text
dotnet build benchmarks/Zorg.Ssh.Benchmarks -c Release
dotnet run -c Release --no-build --project benchmarks/Zorg.Ssh.Benchmarks -- --filter "*"
dotnet run -c Release --no-build --project benchmarks/Zorg.Ssh.Benchmarks -- --ceiling
dotnet run -c Release --no-build --project benchmarks/Zorg.Ssh.Benchmarks -- --phases
```

The full run takes roughly a quarter of an hour with the other two commands (not timed exactly), and needs Podman or Docker.

## Results

One full run. Lower is better for time and memory. `Ratio` is the mean divided by Zorg.Ssh's mean, worked out from the means in the table, not BenchmarkDotNet's per-iteration ratio, which differs a little when the spread is large.

### Exec round trip

| Library | Mean | Std dev | Ratio | Allocated |
|---|---:|---:|---:|---:|
| Zorg.Ssh | 44.3 ms | 0.4 ms | 1.00 | 10.0 KB |
| SSH.NET | 45.0 ms | 1.2 ms | 1.02 | 12.7 KB |
| Tmds.Ssh | 47.7 ms | 2.2 ms | 1.08 | 3.1 KB |

Most of this time is the server starting a process. Zorg.Ssh's allocation was 73 KB on 5 November, mainly two 32 KiB read buffers per command. It is 10 KB now, and the reason wasn't investigated here: the library changed between the two runs.

### Connect and login

| Library | Key exchange | Mean | Std dev | Ratio | Allocated |
|---|---|---:|---:|---:|---:|
| Zorg.Ssh | `curve25519-sha256` | 67.2 ms | 2.6 ms | 1.00 | 49.1 KB |
| SSH.NET | `curve25519-sha256` | 71.4 ms | 2.9 ms | 1.06 | 77.1 KB |
| Tmds.Ssh | `curve25519-sha256` | 111.4 ms | 3.4 ms | 1.66 | 34.9 KB |
| Zorg.Ssh | `mlkem768x25519-sha256` | 68.2 ms | 3.8 ms | 1.00 | 96.7 KB |
| SSH.NET | `mlkem768x25519-sha256` | 87.0 ms | 26.0 ms | 1.27 | 126.3 KB |
| Tmds.Ssh | `mlkem768x25519-sha256` | 110.6 ms | 3.1 ms | 1.62 | 82.1 KB |

The hybrid post-quantum key exchange costs about 1 ms for Zorg.Ssh. SSH.NET's ML-KEM row has a standard deviation of 26 ms, so one slow iteration or more is in it, and its 87 ms shouldn't be read as slower than its 71 ms without ML-KEM.

Timing the two halves separately (`--phases`, medians of 30): login 66.6 ms for Zorg.Ssh, 69.4 ms for SSH.NET and 111.7 ms for Tmds.Ssh. Closing takes 0.2 to 0.3 ms for all three.

Zorg.Ssh used to wait for the server's identification line before sending KEXINIT, and lost about 40 ms to it. It now sends KEXINIT straight after its own identification, as RFC 4253 allows. The cause of the stall was probably a TCP delayed acknowledgement, which would fit the size of the gap, but only the result was measured. It may not show up the same way off this port-forwarded path.

### SFTP: 128 MiB file

| Library | Direction | Cipher | Mean | Std dev | MiB/s | Ratio | Allocated |
|---|---|---|---:|---:|---:|---:|---:|
| Zorg.Ssh | Download | AES-256-GCM | 476 ms | 21 ms | 269 | 1.00 | 6.7 MB |
| SSH.NET | Download | AES-256-GCM | 415 ms | 20 ms | 308 | 0.87 | 9.7 MB |
| Tmds.Ssh | Download | AES-256-GCM | 390 ms | 28 ms | 328 | 0.82 | 0.2 MB |
| Zorg.Ssh | Upload | AES-256-GCM | 454 ms | 83 ms | 282 | 1.00 | 4.6 MB |
| SSH.NET | Upload | AES-256-GCM | 531 ms | 105 ms | 241 | 1.17 | 2.7 MB |
| Tmds.Ssh | Upload | AES-256-GCM | 606 ms | 55 ms | 211 | 1.34 | 0.2 MB |
| Zorg.Ssh | Download | ChaCha20 | 618 ms | 25 ms | 207 | 1.00 | 4.3 MB |
| SSH.NET | Download | ChaCha20 | 588 ms | 22 ms | 218 | 0.95 | 14.0 MB |
| Tmds.Ssh | Download | ChaCha20 | 1,689 ms | 129 ms | 76 | 2.73 | 0.5 MB |
| Zorg.Ssh | Upload | ChaCha20 | 894 ms | 109 ms | 143 | 1.00 | 11.3 MB |
| SSH.NET | Upload | ChaCha20 | 787 ms | 109 ms | 163 | 0.88 | 7.6 MB |
| Tmds.Ssh | Upload | ChaCha20 | 903 ms | 142 ms | 142 | 1.01 | 0.6 MB |

Differences smaller than the standard deviations mean nothing. That covers the AES and ChaCha20 upload rows between Zorg.Ssh and the others, apart from Tmds.Ssh's AES upload, which is 1.3 deviations out. The download rows have deviations of 4% to 7%: SSH.NET and Tmds.Ssh beat Zorg.Ssh on AES download by 13% and 18%, and SSH.NET beat it on ChaCha20 download by 5%, which is just over one deviation.

Zorg.Ssh rekeys after 1 GiB in one direction, and a run moves more than that, so at least one rekey falls inside each Zorg.Ssh upload and download case. It's counted in the result. Whether the other two rekeyed wasn't checked.

### The path itself

Plain TCP through the same published port, with no SSH (`--ceiling`), 1 GiB at a time, five runs each:

| Direction | Slowest | Fastest | Middle |
|---|---:|---:|---:|
| Container to client | 272 MiB/s | 309 MiB/s | 287 MiB/s |
| Client to container | 528 MiB/s | 589 MiB/s | 579 MiB/s |

The path varies from run to run, and it sets the limit on the download rows. Tmds.Ssh's AES download, at 328 MiB/s, ran above this run's fastest plain TCP figure, so the path varied during the run, and a comparison across rows of a few percent says little. In a faster setup the order could differ.

Upload has more room, but the server's `sftp-server` process and file writes also take their share, and those weren't measured apart.

### Cipher throughput

Zorg.Ssh only. In process, on one thread, with a 32 KiB payload, the largest packet a channel sends. Nothing allocates, apart from ChaCha20's 80 bytes per packet in each direction.

| Algorithm | `Seal` | MiB/s | `SealThenOpen` | `Seal`, 1 KiB | `SealThenOpen`, 1 KiB |
|---|---:|---:|---:|---:|---:|
| `aes128-gcm@openssh.com` | 5.0 µs | 6,255 | 10.5 µs | 0.31 µs | 0.63 µs |
| `aes256-gcm@openssh.com` | 6.4 µs | 4,883 | 13.0 µs | 0.35 µs | 0.69 µs |
| `aes256-ctr` with `hmac-sha2-512-etm@openssh.com` | 73.0 µs | 428 | 146.7 µs | 3.0 µs | 6.4 µs |
| `aes128-ctr` with `hmac-sha2-256-etm@openssh.com` | 123.9 µs | 252 | 243.2 µs | 4.7 µs | 9.7 µs |
| `aes256-ctr` with `hmac-sha2-256-etm@openssh.com` | 123.3 µs | 253 | 265.6 µs | 4.6 µs | 9.3 µs |
| `chacha20-poly1305@openssh.com` | 40.3 µs | 775 | 77.8 µs | 1.5 µs | 3.1 µs |

AES-GCM runs on the CPU's AES instructions through the .NET library. ChaCha20-Poly1305 ran on BouncyCastle until 7 November, at 240 MiB/s, about 20 times slower than AES-GCM and close to what Zorg.Ssh reached in ChaCha20 download (207 MiB/s). Its ChaCha20 half is now the library's own vectorised code, and the row above is from that: 775 MiB/s, 3.2 times faster. About 60% of what's left is BouncyCastle's Poly1305 (see [ChaCha20 in vector code](#chacha20-in-vector-code)). The two CTR rows with SHA-256 are slow because this CPU has no SHA-NI, which is why SHA-512 comes first in the MAC list. A newer CPU may give a different order. The `aes256-ctr`/SHA-256 `SealThenOpen` row has a standard deviation of 41 µs (16%), so treat its 265.6 µs as rough.

There's no equivalent figure for the other libraries' ciphers.

## What changed since 5 November

The first measurement used the code at the commit that added this file. Where the tables differ, the library may have changed, and the run-to-run spread is part of the difference.

| Measure | 5 November | 7 November |
|---|---:|---:|
| Login, `curve25519-sha256`, Zorg.Ssh | 109.9 ms (64 ms after the KEXINIT change, by `--phases`) | 67.2 ms |
| Login, SSH.NET | 68.7 ms | 71.4 ms |
| Login, Tmds.Ssh | 108.8 ms | 111.4 ms |
| Exec, Zorg.Ssh | 46.8 ms | 44.3 ms |
| Exec allocation, Zorg.Ssh | 73.1 KB | 10.0 KB |
| AES download, Zorg.Ssh / SSH.NET / Tmds.Ssh | 430 / 415 / 407 ms | 476 / 415 / 390 ms |
| AES upload, Zorg.Ssh / SSH.NET / Tmds.Ssh | 426 / 442 / 667 ms | 454 / 531 / 606 ms |
| ChaCha20 download, Zorg.Ssh / SSH.NET / Tmds.Ssh | 687 / 544 / 1,646 ms | 618 / 588 / 1,689 ms |
| ChaCha20 upload, Zorg.Ssh / SSH.NET / Tmds.Ssh | 913 / 862 / 858 ms | 894 / 787 / 903 ms |
| Plain TCP, container to client | 225 to 282 MiB/s | 272 to 309 MiB/s |

Zorg.Ssh's AES download looked 46 ms slower than on 5 November. It wasn't: see [the AES download check](#the-aes-download-check). Eight alternating runs of each tree gave 422 ms for both, so the 476 ms was noise.

## The AES download check

The 7 November run showed Zorg.Ssh's AES-GCM download at 476 ms, against 430 ms on 5 November, while the other two libraries stayed level. To see whether that was real, the same benchmark (`SftpBenchmarks.ZorgDownload`, identical benchmark code in both trees) ran with the two trees taking turns, eight times each: `000acd1`, the commit the 5 November numbers came from, and `dae2e02`, `main` on 7 November. Each run is a new process and a new container, 2 warmup and 8 measured iterations, as above.

| Tree | Mean of the run means | Spread of the run means | Lowest and highest run |
|---|---:|---:|---:|
| `000acd1` (5 November) | 421 ms | 10 ms (seven runs) | 407 to 440 ms |
| `dae2e02` (7 November) | 422 ms | 5 ms (eight runs) | 414 to 429 ms |

The eighth run of the old tree hit an outlier (one 1,812 ms iteration, median 464 ms) and is left out of the first row. The difference between the trees is 0.4 ms, and the spread inside either tree is 10 times that. **There is no regression.** The 476 ms of 7 November sits far above anything the code did in sixteen further runs (the slowest was 440 ms), so it was a slow moment on the machine, not the code. Because of that, the AES download ranking against SSH.NET and Tmds.Ssh in the table above rests on one run for them and one slow run for Zorg.Ssh, and should be read with that in mind. Neither of the other two was measured again. The ChaCha20 download over the same eight pairs: 645 ms for the old tree, 632 ms for the new one, with a spread of about 20 ms for each, which is also no difference.

## ChaCha20 in vector code

Spike S4 asked whether Zorg.Ssh should carry its own vectorised ChaCha20 instead of BouncyCastle's. It should, and it now does. `ChaCha20Simd` computes four blocks at a time in 256-bit vectors, two in 128-bit vectors (SSE2 and later, Arm AdvSimd) and one in plain integers, picked by what the CPU reports. Poly1305 is still BouncyCastle's. Measured on the machine described above, on `0067522`:

**ChaCha20 alone**, in process, 32 KiB:

| Implementation | Time | MB/s |
|---|---:|---:|
| BouncyCastle `ChaCha7539Engine` | 89 µs | 368 |
| `ChaCha20Simd`, 256-bit | 13.7 µs | 2,390 |
| `ChaCha20Simd`, 128-bit | 25.5 µs | 1,285 |
| `ChaCha20Simd`, plain integers | 70 µs | 466 |

With 1 KiB it is 2.85 µs, 0.44 µs, 0.80 µs and 2.24 µs. Every path beats or matches BouncyCastle, so a machine with no vector support doesn't get slower.

**The packet cipher** (`Seal`, 32 KiB): 130.4 µs before, 40.3 µs now. `SealThenOpen`: 263.5 µs before, 77.8 µs now.

**The SFTP transfer over the container**, Zorg.Ssh only, `main` (`dae2e02`) against the new tree, five pairs taking turns (`ZorgDownload` and `ZorgUpload` with ChaCha20), the same 128 MiB file, 2 warmup and 8 measured iterations each:

| Case | `main`, run means | New, run means | Change in speed |
|---|---|---|---:|
| Download, ChaCha20 | 623 ms (610 to 648) | 508 ms (487 to 537) | 1.23 times |
| Upload, ChaCha20 | 823 ms (758 to 883) | 489 ms (471 to 505) | 1.68 times |

An earlier set of six alternating pairs on the download, in one tree switching between the two implementations, gave 649 ms (616 to 708) against 501 ms (490 to 519), 1.29 times. Over all eleven pairs, the means are 637 and 504 ms (1.26 times) and the medians 620 and 504 ms (1.23 times). **The download speed went up by 23 to 29%, and the upload by 68%.** The download is held back by the path (about 270 to 310 MiB/s) and by the rest of the receive path. At 508 ms it is within 20% of the AES-GCM download in the same runs (422 ms).

The AES-GCM rows in the same runs didn't change: download 422 ms and upload 390 ms for `main`, 423 ms and 381 ms with the new code (means of the run means).

**A faster Poly1305 wasn't worth it.** BouncyCastle's Poly1305 takes 24 µs of the 40 µs for a 32 KiB packet and allocates 80 bytes. A 64-bit-limb version (three 44-bit limbs, `Math.BigMul`) passed the RFC 8439 vectors and a comparison with BouncyCastle for every length from 0 to 4096, but ran at 0.84 to 0.89 times BouncyCastle's time, or 11 to 16% less, and a variant that takes two blocks at a time ran no faster. One written with `UInt128` sums ran 2.5 times slower. That is about 4 µs of the 40 µs, 3% of a download, for new security code, so it wasn't kept. A vectorised Poly1305 would be the way to get more, and nothing here argues for it yet.

**Not measured:** Native AOT (the plan said to check) and Arm. On this machine the AOT default target reported no AVX2 in an earlier spike, so there the 128-bit path would be the one used, at about half the speed above. `Path.Auto` takes whatever `Vector256.IsHardwareAccelerated` says, so it does the right thing, but this was not run.

Noise: another agent's test runs shared the machine for part of this. Most iterations were clean, but single runs had outliers (an AES case at 535 ms, one at 649 ms). The pairs above alternate the trees to spread that. The micro-benchmarks ran with no test process running.

## Limits

- **One machine, one run setup.** No other hardware, operating system or server was tried. A Linux client would avoid the Windows to WSL hop altogether.
- **The network isn't a network.** The round trip is close to zero, so this says little about high latency, where pipelining depth and window sizes matter most. On a real link, all of these results could change order.
- **The path is the limit** for AES-GCM download in the best cases, as above.
- **The server shares the machine,** and its 8 CPUs, with the client. Its work is part of every number, and it's most of the exec number.
- **Noise.** Upload standard deviations reach 20% of the mean. Eight iterations don't settle small differences.
- **One run.** The first measurement had two. This one has one, so run-to-run spread isn't shown, only the spread inside the run.
- **Defaults only.** Each library might do better tuned. Their chunk sizes and pipelining differ, and that's part of what's measured.
- **Single connection, single transfer.** Concurrent channels, many connections, small files and directory listing weren't measured.
- **Client-side memory only.** `Allocated` is managed memory on the client. It doesn't include native memory or peak use.
- **A file over 128 MiB** wasn't tested, so rekey cost in long transfers is only lightly covered.
- **The server isn't benchmarked.** `SshServer` plays no part in these results.
- **It's a pre-release.** Performance work is planned for later, and these numbers will age.
