using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Zorg.Ssh.Connection;
using Zorg.Ssh.Protocol;

namespace Zorg.Ssh.Forwarding;

/// <summary>
/// One tcpip-forward request. An entry joins the table when the server's success reply arrives, in the receive
/// loop, so a connection the server opens straight after that reply finds it. That matters when the server
/// picks the port: nobody knows the port until that moment.
/// </summary>
internal sealed class RemoteForwardEntry(string address, int requestedPort, ForwardScope scope, Func<IncomingChannelOpen, CancellationToken, Task> serve)
{
    public string Address { get; } = address;

    public int RequestedPort { get; } = requestedPort;

    public ForwardScope Scope { get; } = scope;

    public Func<IncomingChannelOpen, CancellationToken, Task> Serve { get; } = serve;

    /// <summary>Gets or sets the port the server bound. Set when the reply arrives.</summary>
    public int BoundPort { get; set; }

    /// <summary>Gets or sets whether the server claimed a port that's already forwarded.</summary>
    public bool Conflict { get; set; }

    /// <summary>Gets or sets whether the caller stopped waiting, so nobody owns this forward.</summary>
    public bool Abandoned { get; set; }
}

/// <summary>
/// The ports we asked a server to forward. Only a connection for one of these is accepted: without this check
/// a server could open channels to whatever a forward targets, whenever it liked.
/// </summary>
internal sealed class RemoteForwardTable
{
    private readonly Lock _gate = new();
    private readonly Dictionary<(string Address, int Port), RemoteForwardEntry> _entries = [];

    /// <summary>Returns whether a forward for this address and port is already there.</summary>
    public bool Contains(string address, int port)
    {
        lock (_gate)
        {
            return _entries.ContainsKey((address, port));
        }
    }

    /// <summary>Handles the reply to tcpip-forward. It runs in the receive loop, so it never waits.</summary>
    public void OnReply(RemoteForwardEntry entry, byte[]? reply)
    {
        if (reply is null)
        {
            return;
        }

        int port = entry.RequestedPort;
        if (port == 0)
        {
            SshReader reader = new(reply);
            uint bound = reader.ReadUInt32();
            if (bound is 0 or > 65535)
            {
                throw new SshProtocolException("The server chose a port that doesn't exist.");
            }

            port = (int)bound;
        }

        lock (_gate)
        {
            entry.BoundPort = port;
            if (!entry.Abandoned)
            {
                entry.Conflict = !_entries.TryAdd((entry.Address, port), entry);
            }
        }
    }

    /// <summary>Marks an entry nobody is waiting for, so a late reply doesn't bring it to life.</summary>
    public void Abandon(RemoteForwardEntry entry)
    {
        lock (_gate)
        {
            entry.Abandoned = true;
            RemoveCore(entry);
        }
    }

    /// <summary>Takes an entry out. From here on the port is refused like any other.</summary>
    public void Remove(RemoteForwardEntry entry)
    {
        lock (_gate)
        {
            RemoveCore(entry);
        }
    }

    /// <summary>
    /// Decides a forwarded-tcpip open, and starts serving it if it's allowed. It runs in the receive loop, so it
    /// never waits. Returns 0, or the reason to refuse with.
    /// </summary>
    public int HandleOpen(IncomingChannelOpen open)
    {
        SshReader reader = new(open.Extra);
        string address = reader.ReadUtf8String();
        uint port = reader.ReadUInt32();

        RemoteForwardEntry? entry;
        lock (_gate)
        {
            if (port > 65535 || !_entries.TryGetValue((address, (int)port), out entry))
            {
                return SshConnection.OpenFailureProhibited;
            }
        }

        if (!entry.Scope.TryReserve())
        {
            return SshConnection.OpenFailureResourceShortage;
        }

        entry.Scope.Run(token => entry.Serve(open, token));
        return 0;
    }

    private void RemoveCore(RemoteForwardEntry entry)
    {
        (string, int) key = (entry.Address, entry.BoundPort);
        if (_entries.TryGetValue(key, out RemoteForwardEntry? found) && ReferenceEquals(found, entry))
        {
            _entries.Remove(key);
        }
    }
}
