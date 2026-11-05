# Benchmarks

Zorg.Ssh measured against SSH.NET 2026.0.0 and Tmds.Ssh 0.26.0, talking to a real OpenSSH server. These are first numbers from one machine, measured on 5 November 2026. Read [the limits](#limits) before you use them for anything.

## Summary

- **Zorg.Ssh isn't faster than the other two overall.** It beat SSH.NET by a margin that repeated in both runs in no test at all. It beat Tmds.Ssh in AES-GCM upload and ChaCha20 download.
- **Login: Zorg.Ssh loses to SSH.NET.** 110 ms against 69 ms, the same as Tmds.Ssh. The cause isn't known.
- **Exec: a tie.** All three take about 45 ms, and most of that is the server. Tmds.Ssh was about 5% ahead in both runs.
- **AES-GCM transfers: no result.** All three ran at about the speed of this machine's network path, so the test can't separate them on download. On upload, Zorg.Ssh and SSH.NET were level, and Tmds.Ssh took 33% to 62% longer than Zorg.Ssh.
- **ChaCha20 transfers: mixed.** SSH.NET's download took 7% to 21% less time than Zorg.Ssh's. Tmds.Ssh's was about 2.5 times slower. Uploads were close to level, with a lot of noise.
- **Memory: Zorg.Ssh allocates the most per command.** 73 KB against 13 KB and 3 KB. In transfers it allocates 8 to 40 times what Tmds.Ssh does, and is about level with SSH.NET.

## Setup

| | |
|---|---|
| Machine | Intel Core i9-9900K at 3.60 GHz, 8 cores and 16 threads, no SHA-NI, 32 GB RAM |
| Operating system | Windows 11 23H2 (10.0.22631) |
| Runtime | .NET 10.0.14, SDK 10.0.403, RyuJIT x86-64-v3, Release build |
| Tool | BenchmarkDotNet 0.15.8 |
| Zorg.Ssh | 0.1.0-alpha, at the commit that adds this file |
| SSH.NET | 2026.0.0 |
| Tmds.Ssh | 0.26.0 |
| Server | OpenSSH_10.6p1 with OpenSSL 3.5.7, on Alpine edge |
| Container | Podman 6.1.4 on a WSL 2 machine with 8 CPUs and 2 GiB, Linux 6.18.54 |
| Path | Client on Windows, through a port published on `127.0.0.1`, to the container |

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

The full run takes about 6.5 minutes, and needs Podman or Docker.

## Results

Two full runs were made. The tables show the second, which started with no other containers or test processes on the machine. The first was noisier, and other work may have been running during it, so its means are given as well. Lower is better for time and memory. `Ratio` is the mean divided by Zorg.Ssh's mean.

### Exec round trip

| Library | Mean | Std dev | Ratio | Allocated | First run |
|---|---:|---:|---:|---:|---:|
| Zorg.Ssh | 46.8 ms | 1.9 ms | 1.00 | 73.1 KB | 46.2 ms |
| SSH.NET | 45.1 ms | 1.7 ms | 0.97 | 12.7 KB | 46.0 ms |
| Tmds.Ssh | 44.0 ms | 0.3 ms | 0.94 | 3.1 KB | 44.1 ms |

Most of this time is the server starting a process. Zorg.Ssh's allocation is mainly the two 32 KiB read buffers that `ExecuteAsync` makes for each command.

### Connect and login

| Library | Key exchange | Mean | Std dev | Ratio | Allocated | First run |
|---|---|---:|---:|---:|---:|---:|
| Zorg.Ssh | `curve25519-sha256` | 109.9 ms | 1.9 ms | 1.00 | 46.7 KB | 108.9 ms |
| SSH.NET | `curve25519-sha256` | 68.7 ms | 1.1 ms | 0.63 | 77.1 KB | 73.3 ms |
| Tmds.Ssh | `curve25519-sha256` | 108.8 ms | 1.5 ms | 0.99 | 34.7 KB | 111.4 ms |
| Zorg.Ssh | `mlkem768x25519-sha256` | 110.6 ms | 1.8 ms | 1.00 | 94.5 KB | 112.8 ms |
| SSH.NET | `mlkem768x25519-sha256` | 69.3 ms | 1.4 ms | 0.63 | 126.3 KB | 70.0 ms |
| Tmds.Ssh | `mlkem768x25519-sha256` | 110.5 ms | 1.9 ms | 1.00 | 82.0 KB | 112.5 ms |

The hybrid post-quantum key exchange costs almost nothing here.

Timing the two halves separately (`--phases`, medians of 30) puts the whole gap in login: 108.1 ms for Zorg.Ssh, 67.8 ms for SSH.NET and 107.7 ms for Tmds.Ssh. Closing takes under 0.5 ms for all three.

**The 40 ms gap isn't explained.** It's the same size for Zorg.Ssh and Tmds.Ssh, and it's about the length of a TCP delayed acknowledgement, so it may be a stall in the protocol exchange rather than computing time. That's a guess. It could also be specific to this port-forwarded path. Nobody has looked into it yet.

### SFTP: 128 MiB file

| Library | Direction | Cipher | Mean | Std dev | MiB/s | Ratio | Allocated | First run |
|---|---|---|---:|---:|---:|---:|---:|---:|
| Zorg.Ssh | Download | AES-256-GCM | 430 ms | 18 ms | 298 | 1.00 | 6.4 MB | 456 ms |
| SSH.NET | Download | AES-256-GCM | 415 ms | 8 ms | 308 | 0.97 | 9.8 MB | 432 ms |
| Tmds.Ssh | Download | AES-256-GCM | 407 ms | 26 ms | 315 | 0.95 | 0.2 MB | 624 ms |
| Zorg.Ssh | Upload | AES-256-GCM | 426 ms | 96 ms | 301 | 1.00 | 4.4 MB | 506 ms |
| SSH.NET | Upload | AES-256-GCM | 442 ms | 16 ms | 289 | 1.07 | 2.7 MB | 439 ms |
| Tmds.Ssh | Upload | AES-256-GCM | 667 ms | 75 ms | 192 | 1.62 | 0.2 MB | 673 ms |
| Zorg.Ssh | Download | ChaCha20 | 687 ms | 38 ms | 186 | 1.00 | 4.1 MB | 683 ms |
| SSH.NET | Download | ChaCha20 | 544 ms | 28 ms | 235 | 0.79 | 14.0 MB | 638 ms |
| Tmds.Ssh | Download | ChaCha20 | 1,646 ms | 89 ms | 78 | 2.40 | 0.5 MB | 1,790 ms |
| Zorg.Ssh | Upload | ChaCha20 | 913 ms | 124 ms | 140 | 1.00 | 11.2 MB | 893 ms |
| SSH.NET | Upload | ChaCha20 | 862 ms | 107 ms | 149 | 0.96 | 7.6 MB | 731 ms |
| Tmds.Ssh | Upload | ChaCha20 | 858 ms | 129 ms | 149 | 0.96 | 0.6 MB | 918 ms |

The first run's Tmds.Ssh AES download of 624 ms had a large outlier: its median was 481 ms.

Differences smaller than the standard deviations here mean nothing. That covers most of the upload rows. SSH.NET beat Zorg.Ssh on ChaCha20 download in both runs, by 7% in the first and 21% in the second, and on ChaCha20 upload in both. Zorg.Ssh's AES upload was ahead in the second run and behind in the first.

Zorg.Ssh rekeys after 1 GiB in one direction, and a run moves more than that, so at least one rekey falls inside each Zorg.Ssh upload and download case. It's counted in the result. Whether the other two rekeyed wasn't checked.

### The path itself

Plain TCP through the same published port, with no SSH (`--ceiling`), 1 GiB at a time, five runs each:

| Direction | Slowest | Fastest | Middle |
|---|---:|---:|---:|
| Container to client | 225 MiB/s | 282 MiB/s | 270 MiB/s |
| Client to container | 524 MiB/s | 667 MiB/s | 545 MiB/s |

Downloads with AES-GCM ran at or just above this figure. The path varies from run to run, and it sets the limit on that row of the table. So the AES download results say that no library is much slower than the path, and nothing about which is fastest. In a faster setup the order could differ.

Upload has more room, but the server's `sftp-server` process and file writes also take their share, and those weren't measured apart.

### Cipher throughput

Zorg.Ssh only. In process, on one thread, with a 32 KiB payload, the largest packet a channel sends. Nothing allocates, apart from ChaCha20's 80 bytes per packet in each direction.

| Algorithm | `Seal` | MiB/s | `SealThenOpen` | `Seal`, 1 KiB | `SealThenOpen`, 1 KiB |
|---|---:|---:|---:|---:|---:|
| `aes128-gcm@openssh.com` | 5.1 µs | 6,159 | 10.6 µs | 0.30 µs | 0.63 µs |
| `aes256-gcm@openssh.com` | 6.6 µs | 4,704 | 13.1 µs | 0.35 µs | 0.70 µs |
| `aes256-ctr` with `hmac-sha2-512-etm@openssh.com` | 73.8 µs | 424 | 148.0 µs | 3.1 µs | 6.4 µs |
| `aes128-ctr` with `hmac-sha2-256-etm@openssh.com` | 123.1 µs | 254 | 253.3 µs | 4.6 µs | 9.4 µs |
| `aes256-ctr` with `hmac-sha2-256-etm@openssh.com` | 126.4 µs | 247 | 251.7 µs | 4.7 µs | 9.5 µs |
| `chacha20-poly1305@openssh.com` | 138.4 µs | 226 | 270.2 µs | 4.6 µs | 9.4 µs |

AES-GCM runs on the CPU's AES instructions through the .NET library. ChaCha20-Poly1305 runs on BouncyCastle, about 20 times slower here. Its 226 MiB/s is close to what Zorg.Ssh reaches in ChaCha20 download, so the cipher is the likely limit there, not the network. The two CTR rows with SHA-256 are slow because this CPU has no SHA-NI, which is why SHA-512 comes first in the MAC list. A newer CPU may give a different order.

There's no equivalent figure for the other libraries' ciphers.

## Limits

- **One machine, one run setup.** No other hardware, operating system or server was tried. A Linux client would avoid the Windows to WSL hop altogether.
- **The network isn't a network.** The round trip is close to zero, so this says little about high latency, where pipelining depth and window sizes matter most. On a real link, all of these results could change order.
- **The path is the limit** for AES-GCM download, as above.
- **The server shares the machine,** and its 8 CPUs, with the client. Its work is part of every number, and it's most of the exec number.
- **Noise.** Upload standard deviations reach 23% of the mean. Eight iterations don't settle small differences. BenchmarkDotNet also warned of a multimodal distribution for some cases.
- **Two runs.** The second is in the tables because it was the last, on the final code, not because of what it showed. Both are given so you can compare.
- **Defaults only.** Each library might do better tuned. Their chunk sizes and pipelining differ, and that's part of what's measured.
- **Single connection, single transfer.** Concurrent channels, many connections, small files and directory listing weren't measured.
- **Client-side memory only.** `Allocated` is managed memory on the client. It doesn't include native memory or peak use.
- **A file over 128 MiB** wasn't tested, so rekey cost in long transfers is only lightly covered.
- **The server isn't benchmarked.** `SshServer` plays no part in these results.
- **It's a pre-release.** Performance work is planned for later, and these numbers will age.
