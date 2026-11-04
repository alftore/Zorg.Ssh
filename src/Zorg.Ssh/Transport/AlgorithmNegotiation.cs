using System;
using System.Collections.Generic;
using System.Linq;

namespace Zorg.Ssh.Transport;

/// <summary>The names that aren't algorithms: they ride in the KEX list to signal extensions.</summary>
internal static class KexMarkers
{
    public const string StrictClientV00 = "kex-strict-c-v00@openssh.com";
    public const string StrictServerV00 = "kex-strict-s-v00@openssh.com";
    public const string StrictClient = "kex-strict-c";
    public const string StrictServer = "kex-strict-s";
    public const string ExtInfoClient = "ext-info-c";
    public const string ExtInfoServer = "ext-info-s";

    public static bool IsMarker(string name) =>
        name is StrictClientV00 or StrictServerV00 or StrictClient or StrictServer or ExtInfoClient or ExtInfoServer;

    /// <summary>
    /// Decides whether strict KEX applies, from the peer's first KEXINIT. We offer both name forms, so any
    /// peer marker matches one of ours. Only the marker of the peer's own role counts.
    /// </summary>
    public static bool PeerOffersStrict(SshRole ourRole, IReadOnlyList<string> peerKex) =>
        ourRole == SshRole.Client
            ? peerKex.Contains(StrictServerV00) || peerKex.Contains(StrictServer)
            : peerKex.Contains(StrictClientV00) || peerKex.Contains(StrictClient);

    public static bool PeerOffersExtInfo(SshRole ourRole, IReadOnlyList<string> peerKex) =>
        peerKex.Contains(ourRole == SshRole.Client ? ExtInfoServer : ExtInfoClient);
}

/// <summary>The result of comparing two KEXINIT messages.</summary>
internal sealed record NegotiatedAlgorithms(
    string Kex,
    string HostKey,
    string CipherClientToServer,
    string CipherServerToClient,
    string? MacClientToServer,
    string? MacServerToClient,
    bool PeerGuessWrong);

/// <summary>RFC 4253 section 7.1: for each family, the first client name the server also has.</summary>
internal static class AlgorithmNegotiation
{
    public static NegotiatedAlgorithms Negotiate(
        SshRole ourRole,
        KexInitMessage ours,
        KexInitMessage peer,
        Func<string, bool> isAead)
    {
        KexInitMessage client = ourRole == SshRole.Client ? ours : peer;
        KexInitMessage server = ourRole == SshRole.Client ? peer : ours;

        string kex = Choose("key exchange", ourRole, client.KexAlgorithms, server.KexAlgorithms, static n => !KexMarkers.IsMarker(n));
        string hostKey = Choose("host key", ourRole, client.HostKeyAlgorithms, server.HostKeyAlgorithms);
        string cipherCs = Choose("client-to-server cipher", ourRole, client.CiphersClientToServer, server.CiphersClientToServer);
        string cipherSc = Choose("server-to-client cipher", ourRole, client.CiphersServerToClient, server.CiphersServerToClient);
        string? macCs = isAead(cipherCs) ? null : Choose("client-to-server MAC", ourRole, client.MacsClientToServer, server.MacsClientToServer);
        string? macSc = isAead(cipherSc) ? null : Choose("server-to-client MAC", ourRole, client.MacsServerToClient, server.MacsServerToClient);
        Choose("client-to-server compression", ourRole, client.CompressionClientToServer, server.CompressionClientToServer);
        Choose("server-to-client compression", ourRole, client.CompressionServerToClient, server.CompressionServerToClient);

        // A guess is right when both sides list the same first choices, as OpenSSH checks it.
        bool guessRight = client.KexAlgorithms.Count > 0 && server.KexAlgorithms.Count > 0
            && client.HostKeyAlgorithms.Count > 0 && server.HostKeyAlgorithms.Count > 0
            && client.KexAlgorithms[0] == server.KexAlgorithms[0]
            && client.HostKeyAlgorithms[0] == server.HostKeyAlgorithms[0];

        return new NegotiatedAlgorithms(kex, hostKey, cipherCs, cipherSc, macCs, macSc, peer.FirstKexPacketFollows && !guessRight);
    }

    private static string Choose(
        string family,
        SshRole ourRole,
        IReadOnlyList<string> client,
        IReadOnlyList<string> server,
        Func<string, bool>? filter = null)
    {
        foreach (string name in client)
        {
            if ((filter is null || filter(name)) && server.Contains(name))
            {
                return name;
            }
        }

        throw ourRole == SshRole.Client
            ? new SshNegotiationException(family, client, server)
            : new SshNegotiationException(family, server, client);
    }
}
