using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Zorg.Ssh.Protocol;

namespace Zorg.Ssh.Crypto.KeyExchange;

/// <summary>
/// A fixed MODP group from RFC 3526, with generator 2. The primes are safe primes (p = 2q + 1, q prime), written here
/// exactly as RFC 3526 gives them.
/// </summary>
internal sealed class DiffieHellmanGroup
{
    // RFC 3526 section 3: the 2048-bit MODP group, 2^2048 - 2^1984 - 1 + 2^64 * { [2^1918 pi] + 124476 }. SSH's group 14.
    private const string Prime2048 =
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74" +
        "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437" +
        "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05" +
        "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB" +
        "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" +
        "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

    // RFC 3526 section 5: the 4096-bit MODP group, 2^4096 - 2^4032 - 1 + 2^64 * { [2^3966 pi] + 240904 }. SSH's group 16.
    private const string Prime4096 =
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74" +
        "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437" +
        "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05" +
        "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB" +
        "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" +
        "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33" +
        "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
        "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864" +
        "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2" +
        "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7" +
        "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8" +
        "DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2" +
        "233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9" +
        "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF";

    private static readonly Lazy<DiffieHellmanGroup> Lazy14 = new(() => new DiffieHellmanGroup(Prime2048));
    private static readonly Lazy<DiffieHellmanGroup> Lazy16 = new(() => new DiffieHellmanGroup(Prime4096));

    private DiffieHellmanGroup(string primeHex)
    {
        Prime = Convert.FromHexString(primeHex);
        Arithmetic = new MontgomeryModPow(Prime);
        Bits = Prime.Length * 8;
        PrimeMinusOne = Arithmetic.Modulus.ToArray();

        // p is odd, so p - 1 only clears the low bit.
        PrimeMinusOne[0] &= ~1UL;
    }

    /// <summary>Gets the 2048-bit group, <c>diffie-hellman-group14-*</c>.</summary>
    public static DiffieHellmanGroup Group14 => Lazy14.Value;

    /// <summary>Gets the 4096-bit group, <c>diffie-hellman-group16-*</c>.</summary>
    public static DiffieHellmanGroup Group16 => Lazy16.Value;

    /// <summary>Gets the prime, big-endian.</summary>
    public byte[] Prime { get; }

    /// <summary>Gets the prime's size in bits.</summary>
    public int Bits { get; }

    /// <summary>Gets the arithmetic modulo the prime.</summary>
    public MontgomeryModPow Arithmetic { get; }

    /// <summary>Gets p - 1, in limbs, the bound a peer's value must stay under.</summary>
    public ulong[] PrimeMinusOne { get; }
}

/// <summary>
/// <c>diffie-hellman-group14-sha256</c>, <c>diffie-hellman-group16-sha512</c> (RFC 8268) and <c>diffie-hellman-group14-sha1</c>
/// (RFC 4253 section 8), legacy and opt-in only. The client sends e = g^x mod p in KEXDH_INIT (30), the server answers
/// with f = g^y mod p in KEXDH_REPLY (31): the same messages and the same shape as ECDH, so the transport and its message
/// policy don't change. e, f and K are mpints.
/// </summary>
/// <remarks>
/// <para>
/// The secret exponent and every intermediate value live in pinned limb arrays that are zeroed when they are done with,
/// and the exponentiation is constant-time (<see cref="MontgomeryModPow"/>). <see cref="System.Numerics.BigInteger"/> is
/// never given a secret.
/// </para>
/// <para>
/// The exponent has OpenSSH's size (<c>dh_gen_key</c>): twice the bits of the largest key the session derives, at least 512
/// bits, and below the prime's size. Its top bit is set, so it's at least 2^(bits-1), well inside [2, p - 2].
/// </para>
/// <para>
/// Cost, for guarantee 3: one handshake is two exponentiations, about 9 ms each for group 14 and 17 to 29 ms for group 16 on the development
/// x64 machine. On a server that is CPU a client can make it spend before logging in, so a server offers these only
/// when its key exchange list names them.
/// </para>
/// </remarks>
internal sealed class FiniteFieldDhKeyExchange : KeyExchangeMethod
{
    private const int MinimumExponentBits = 512;

    private readonly DiffieHellmanGroup _group;
    private readonly int _exponentBits;
    private ulong[]? _exponent;
    private bool _started;

    /// <summary>Creates one exchange.</summary>
    /// <param name="group">The group.</param>
    /// <param name="hash">The exchange hash.</param>
    /// <param name="keyNeedBytes">The longest key, IV or MAC key the session will derive, in bytes, which sets the exponent size.</param>
    /// <param name="exponent">For known-answer tests only: a fixed exponent, big-endian. This instance then owns its copy.</param>
    public FiniteFieldDhKeyExchange(DiffieHellmanGroup group, HashAlgorithmName hash, int keyNeedBytes, ReadOnlySpan<byte> exponent = default)
    {
        _group = group;
        HashAlgorithm = hash;
        _exponentBits = ExponentBits(group.Bits, keyNeedBytes);
        if (!exponent.IsEmpty)
        {
            _exponent = NewSecret();
            if (!MontgomeryModPow.TryReadLimbs(exponent, _exponent))
            {
                throw new ArgumentException("The exponent is wider than the group.", nameof(exponent));
            }

            _exponentBits = group.Bits;
        }
    }

    /// <inheritdoc/>
    public override HashAlgorithmName HashAlgorithm { get; }

    /// <summary>Gets OpenSSH's exponent size, in bits, for a prime of <paramref name="primeBits"/> and a session needing <paramref name="keyNeedBytes"/>.</summary>
    public static int ExponentBits(int primeBits, int keyNeedBytes) =>
        Math.Min(Math.Max(keyNeedBytes * 8, MinimumExponentBits / 2) * 2, primeBits - 1);

    /// <inheritdoc/>
    public override byte[] CreateClientPublicValue()
    {
        Start();
        return PublicValue();
    }

    /// <inheritdoc/>
    public override byte[] ClientComputeSharedSecret(ReadOnlySpan<byte> serverPublicValue)
    {
        if (_exponent is null || !_started)
        {
            throw new InvalidOperationException("Create the client public value first.");
        }

        try
        {
            return SharedSecret(serverPublicValue);
        }
        finally
        {
            ClearExponent();
        }
    }

    /// <inheritdoc/>
    public override byte[] ServerRespond(ReadOnlySpan<byte> clientPublicValue, out byte[] encodedSharedSecret)
    {
        Start();
        try
        {
            // The client's value is checked before any exponentiation is spent on it.
            ulong[] peer = ReadPeerValue(clientPublicValue);
            byte[] publicValue = PublicValue();
            encodedSharedSecret = SharedSecret(peer);
            return publicValue;
        }
        finally
        {
            ClearExponent();
        }
    }

    /// <summary>
    /// Reads and checks a peer's public value, given as the body of its mpint. It must be positive, at most one byte wider than
    /// the prime (room for the sign byte), and 1 &lt; value &lt; p - 1 (RFC 4253 section 8). Redundant leading zero bytes are
    /// accepted within that width, as OpenSSH accepts them; the exchange hash takes the bytes exactly as they arrived.
    /// Anything else throws <see cref="SshProtocolException"/>. The value is public, so this needn't be constant-time.
    /// </summary>
    public ulong[] ReadPeerValue(ReadOnlySpan<byte> mpintBody)
    {
        MontgomeryModPow arithmetic = _group.Arithmetic;
        if (mpintBody.Length > arithmetic.ByteLength + 1 || (!mpintBody.IsEmpty && (mpintBody[0] & 0x80) != 0))
        {
            throw InvalidPeerValue();
        }

        ulong[] value = new ulong[arithmetic.Limbs];
        if (!MontgomeryModPow.TryReadLimbs(mpintBody, value)
            || MontgomeryModPow.ComparePublic(value, _group.PrimeMinusOne) >= 0
            || IsAtMostOne(value))
        {
            throw InvalidPeerValue();
        }

        return value;
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            ClearExponent();
        }

        base.Dispose(disposing);
    }

    private static bool IsAtMostOne(ReadOnlySpan<ulong> value)
    {
        for (int i = 1; i < value.Length; i++)
        {
            if (value[i] != 0)
            {
                return false;
            }
        }

        return value[0] <= 1;
    }

    private static SshProtocolException InvalidPeerValue() =>
        new("The peer sent an invalid Diffie-Hellman public value, so the key exchange failed. Check that the peer is a real SSH implementation.");

    /// <summary>Encodes a magnitude as the body of an mpint: no redundant zeros, and a zero byte in front if the top bit is set.</summary>
    private static byte[] MPIntBody(ReadOnlySpan<byte> magnitude)
    {
        SshWriter writer = new(magnitude.Length + 5);
        try
        {
            writer.WriteMPInt(magnitude);
            return writer.Written[4..].ToArray();
        }
        finally
        {
            writer.Dispose();
        }
    }

    private ulong[] NewSecret() => GC.AllocateArray<ulong>(_group.Arithmetic.Limbs, pinned: true);

    private void Start()
    {
        if (_started)
        {
            throw new InvalidOperationException("A key exchange instance runs one exchange only.");
        }

        _started = true;
        if (_exponent is null)
        {
            // _exponentBits random bits with the top one set (dh_gen_key and OpenSSL's DH_generate_key do the same).
            _exponent = NewSecret();
            RandomNumberGenerator.Fill(MemoryMarshal.AsBytes(_exponent.AsSpan()));
            int full = _exponentBits / 64;
            int partial = _exponentBits % 64;
            if (partial != 0)
            {
                _exponent[full] &= (1UL << partial) - 1;
                full++;
            }

            _exponent.AsSpan(full).Clear();
            _exponent[(_exponentBits - 1) / 64] |= 1UL << ((_exponentBits - 1) % 64);
        }
    }

    /// <summary>g^x mod p, as an mpint body. Public, so the plain encoding is fine.</summary>
    private byte[] PublicValue()
    {
        MontgomeryModPow arithmetic = _group.Arithmetic;
        ulong[] generator = new ulong[arithmetic.Limbs];
        generator[0] = 2;
        ulong[] result = new ulong[arithmetic.Limbs];
        arithmetic.Pow(generator, _exponent, _exponentBits, result);
        byte[] magnitude = new byte[arithmetic.ByteLength];
        MontgomeryModPow.WriteBigEndian(result, magnitude);
        return MPIntBody(magnitude);
    }

    private byte[] SharedSecret(ReadOnlySpan<byte> peerMPIntBody) => SharedSecret(ReadPeerValue(peerMPIntBody));

    /// <summary>K = peer^x mod p, encoded as an mpint with its length, ready for the exchange hash and key derivation.</summary>
    private byte[] SharedSecret(ulong[] peer)
    {
        MontgomeryModPow arithmetic = _group.Arithmetic;
        ulong[] shared = NewSecret();
        byte[] magnitude = GC.AllocateArray<byte>(arithmetic.ByteLength, pinned: true);
        try
        {
            arithmetic.Pow(peer, _exponent, _exponentBits, shared);

            // RFC 4251 section 5: K as an mpint. The magnitude is the prime's width, so SshWriter drops leading zero bytes
            // and puts a zero byte in front when the top bit is set. Both happen by chance (1 in 256 and 1 in 2), and
            // getting either wrong breaks the exchange hash only for that run: the classic interop bug.
            MontgomeryModPow.WriteBigEndian(shared, magnitude);
            return SharedSecretEncoding.EncodeMPInt(magnitude);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(shared.AsSpan()));
            CryptographicOperations.ZeroMemory(magnitude);
        }
    }

    private void ClearExponent()
    {
        if (_exponent is not null)
        {
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(_exponent.AsSpan()));
            _exponent = null;
        }
    }
}
