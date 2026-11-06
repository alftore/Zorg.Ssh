using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;

namespace Zorg.Ssh;

/// <summary>
/// Counts connections that haven't logged in yet, per source address (R10). An entry exists only while its count
/// is above zero, so the table can never hold more entries than there are counted connections, which the caller
/// bounds with <see cref="SshServerOptions.MaxUnauthenticatedConnections"/>.
/// </summary>
internal sealed class PerAddressLimiter
{
    private readonly object _lock = new();
    private readonly Dictionary<IPAddress, int> _counts = [];
    private readonly int _limit;

    public PerAddressLimiter(int limit)
    {
        _limit = limit;
    }

    /// <summary>Gets the number of addresses with a counted connection. Zero when nothing is counted.</summary>
    public int Entries
    {
        get
        {
            lock (_lock)
            {
                return _counts.Count;
            }
        }
    }

    /// <summary>
    /// Maps an address to the key it is counted under: an IPv4-mapped IPv6 address becomes its IPv4 address, and
    /// any other IPv6 address becomes its /64 prefix, because one host commonly owns a whole /64.
    /// </summary>
    public static IPAddress KeyFor(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (address.IsIPv4MappedToIPv6)
            {
                return address.MapToIPv4();
            }

            Span<byte> bytes = stackalloc byte[16];
            address.TryWriteBytes(bytes, out _);
            bytes[8..].Clear();
            return new IPAddress(bytes);
        }

        return address;
    }

    /// <summary>Takes a count for the address's key. Returns false, and takes nothing, if it is at the limit.</summary>
    public bool TryAcquire(IPAddress address)
    {
        IPAddress key = KeyFor(address);
        lock (_lock)
        {
            _counts.TryGetValue(key, out int count);
            if (count >= _limit)
            {
                return false;
            }

            _counts[key] = count + 1;
            return true;
        }
    }

    /// <summary>Gives back a count taken with <see cref="TryAcquire"/>, and drops the entry at zero.</summary>
    public void Release(IPAddress address)
    {
        IPAddress key = KeyFor(address);
        lock (_lock)
        {
            if (!_counts.TryGetValue(key, out int count))
            {
                return;
            }

            if (count <= 1)
            {
                _counts.Remove(key);
            }
            else
            {
                _counts[key] = count - 1;
            }
        }
    }
}
