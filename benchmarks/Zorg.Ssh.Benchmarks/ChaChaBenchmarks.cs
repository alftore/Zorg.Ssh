using System;
using System.Buffers.Binary;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Environments;
using BenchmarkDotNet.Jobs;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Crypto.Ciphers;

namespace Zorg.Ssh.Benchmarks;

/// <summary>Spike S4: ChaCha20 alone, and the whole packet cipher, BouncyCastle against the vectorised code.</summary>
[Config(typeof(Settings))]
#pragma warning disable CA1001 // BenchmarkDotNet calls the GlobalCleanup method.
public class ChaChaBenchmarks
{
    private const int Tag = 16;

    private byte[] _data = null!;
    private byte[] _out = null!;
    private uint[] _words = null!;
    private ChaCha7539Engine _engine = null!;
    private PacketCipher _simd = null!;
    private byte[] _packet = null!;
    private uint _sequence;

    [Params(1024, 32768)]
    public int Size { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        byte[] key = new byte[64];
        new Random(1).NextBytes(key);
        _data = new byte[Size];
        _out = new byte[Size];
        new Random(2).NextBytes(_data);
        _words = new uint[8];
        ChaCha20Simd.LoadKey(key.AsSpan(0, 32), _words);
        _engine = new ChaCha7539Engine();
        _engine.Init(true, new ParametersWithIV(new KeyParameter(key, 0, 32), new byte[12]));
        _simd = new ChaCha20Poly1305Cipher(key);

        int body = ((Size + 1 + 4 + 7) / 8) * 8;
        _packet = new byte[4 + body + Tag];
        _packet[4] = (byte)(body - 1 - Size);
        BinaryPrimitives.WriteUInt32BigEndian(_packet, (uint)body);
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _simd.Dispose();
    }

    [Benchmark(Baseline = true)]
    [BenchmarkCategory("ChaCha20")]
    public void BouncyCastle() => _engine.ProcessBytes(_data, 0, Size, _out, 0);

    [Benchmark]
    [BenchmarkCategory("ChaCha20")]
    public void SimdAuto() => ChaCha20Simd.Crypt(_words, 1, 0, 7, _data, _out);

    [Benchmark]
    [BenchmarkCategory("ChaCha20")]
    public void SimdVector128() => ChaCha20Simd.Crypt(_words, 1, 0, 7, _data, _out, ChaCha20Simd.Path.Vector128);

    [Benchmark]
    [BenchmarkCategory("ChaCha20")]
    public void SimdScalar() => ChaCha20Simd.Crypt(_words, 1, 0, 7, _data, _out, ChaCha20Simd.Path.Scalar);

    [Benchmark]
    [BenchmarkCategory("Seal")]
    public void Seal()
    {
        BinaryPrimitives.WriteUInt32BigEndian(_packet, (uint)(_packet.Length - 4 - Tag));
        _simd.Seal(_packet, _sequence++);
    }

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
            AddLogicalGroupRules(BenchmarkLogicalGroupRule.ByCategory, BenchmarkLogicalGroupRule.ByParams);
        }
    }
}
