using System;
using System.Buffers.Binary;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Environments;
using BenchmarkDotNet.Jobs;
using Zorg.Ssh.Crypto;

namespace Zorg.Ssh.Benchmarks;

/// <summary>
/// The packet ciphers alone, in process, with no network. <c>Seal</c> is the sending path, and <c>SealThenOpen</c>
/// is both ends of a packet. A cipher can't open a packet twice, so opening isn't timed on its own.
/// </summary>
[Config(typeof(Settings))]
public class CipherBenchmarks
{
    private const int LengthField = 4;
    private const int MinPadding = 4;

    private PacketCipher _sender = null!;
    private PacketCipher _receiver = null!;
    private byte[] _packet = null!;
    private uint _bodyLength;
    private uint _sequence;

    [Params(
        "aes128-gcm@openssh.com",
        "aes256-gcm@openssh.com",
        "chacha20-poly1305@openssh.com",
        "aes128-ctr+hmac-sha2-256-etm@openssh.com",
        "aes256-ctr+hmac-sha2-256-etm@openssh.com",
        "aes256-ctr+hmac-sha2-512-etm@openssh.com")]
    public string Algorithm { get; set; } = "aes256-gcm@openssh.com";

    [Params(1024, 32768)]
    public int Payload { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        string[] names = Algorithm.Split('+');
        string? mac = names.Length > 1 ? names[1] : null;
        CipherInfo cipher = PacketCipherCatalog.FindCipher(names[0])!;
        byte[] key = Bytes(cipher.KeyLength, 1);
        byte[] iv = Bytes(cipher.IvLength, 2);
        byte[] macKey = mac is null ? [] : Bytes(PacketCipherCatalog.FindMac(mac)!.KeyLength, 3);
        _sender = PacketCipherCatalog.Create(names[0], mac, key, iv, macKey);
        _receiver = PacketCipherCatalog.Create(names[0], mac, key, iv, macKey);

        int block = _sender.BlockSize;
        int padding = block - ((1 + Payload) % block);
        if (padding < MinPadding)
        {
            padding += block;
        }

        _bodyLength = (uint)(1 + Payload + padding);
        _packet = new byte[LengthField + _bodyLength + _sender.TagLength];
        _packet[LengthField] = (byte)padding;
        WriteLength();
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _sender.Dispose();
        _receiver.Dispose();
    }

    [Benchmark]
    public void Seal()
    {
        // ChaCha20 encrypts the length, so each packet needs it written again. It costs nanoseconds.
        WriteLength();
        _sender.Seal(_packet, _sequence++);
    }

    [Benchmark]
    public void SealThenOpen()
    {
        _sender.Seal(_packet, _sequence);
        _receiver.Open(_packet, _sequence);
        _sequence++;
    }

    private static byte[] Bytes(int count, byte value)
    {
        byte[] bytes = new byte[count];
        Array.Fill(bytes, value);
        return bytes;
    }

    private void WriteLength() => BinaryPrimitives.WriteUInt32BigEndian(_packet, _bodyLength);

    private sealed class Settings : ManualConfig
    {
        public Settings()
        {
            AddJob(Job.Default
                .WithWarmupCount(3)
                .WithIterationCount(8)
                .WithIterationTime(Perfolizer.Horology.TimeInterval.FromMilliseconds(100))
                .WithPowerPlan(PowerPlan.UserPowerPlan)
                .WithArguments(PeerConfig.GeneratedProject));
            AddDiagnoser(BenchmarkDotNet.Diagnosers.MemoryDiagnoser.Default);
        }
    }
}
