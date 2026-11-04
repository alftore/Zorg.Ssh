using System;

namespace Zorg.Ssh.Crypto;

/// <summary>
/// Protects packets in one direction. A packet in a buffer is laid out as RFC 4253 section 6 describes:
/// <c>uint32 packet_length</c>, then the body (<c>byte padding_length</c>, payload, padding), then <see cref="TagLength"/>
/// bytes of authentication tag. An instance is not thread-safe, and belongs to one send or receive path.
/// </summary>
internal abstract class PacketCipher : IDisposable
{
    /// <summary>Gets the padding alignment, at least 8.</summary>
    public abstract int BlockSize { get; }

    /// <summary>Gets the length of the tag after each packet. Zero only before the first key exchange.</summary>
    public abstract int TagLength { get; }

    /// <summary>
    /// Gets whether the 4-byte length field is left out of the padding calculation. True for AEAD and
    /// encrypt-then-MAC, where the length isn't part of the padded ciphertext.
    /// </summary>
    public abstract bool LengthExcludedFromPadding { get; }

    /// <summary>
    /// Reads <c>packet_length</c> from the first 4 bytes of an incoming packet, without changing them. The
    /// value is untrusted until <see cref="Open"/> succeeds, and the caller checks it against its limits.
    /// </summary>
    public abstract uint ReadPacketLength(ReadOnlySpan<byte> header, uint sequenceNumber);

    /// <summary>
    /// Authenticates, then decrypts in place. <paramref name="packet"/> holds the length field, the body and
    /// the tag. On return, the body is plaintext at offset 4. Implementations verify before releasing any
    /// plaintext, compare tags in constant time, and throw <see cref="SshProtocolException"/> on failure.
    /// Malformed input must never produce another exception type.
    /// </summary>
    public abstract void Open(Span<byte> packet, uint sequenceNumber);

    /// <summary>
    /// Encrypts in place and writes the tag. <paramref name="packet"/> holds the plaintext length field and
    /// padded body, followed by <see cref="TagLength"/> free bytes.
    /// </summary>
    public abstract void Seal(Span<byte> packet, uint sequenceNumber);

    /// <summary>Zeroes and releases key material.</summary>
    public void Dispose()
    {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }

    /// <summary>Zeroes and releases key material.</summary>
    protected virtual void Dispose(bool disposing)
    {
    }
}
