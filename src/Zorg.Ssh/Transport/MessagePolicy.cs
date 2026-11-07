using Zorg.Ssh.Protocol;

namespace Zorg.Ssh.Transport;

/// <summary>The side of a connection.</summary>
internal enum SshRole
{
    Client,
    Server,
}

/// <summary>Where a connection is in its life. See the table in the transport design.</summary>
internal enum TransportPhase
{
    InitialKex,
    AwaitService,
    Auth,
    Connected,
}

/// <summary>What to do with an incoming message.</summary>
internal enum MessageDecision
{
    /// <summary>Process it.</summary>
    Handle,

    /// <summary>Reply with SSH_MSG_UNIMPLEMENTED and carry on (RFC 4253 section 11.4).</summary>
    Unimplemented,

    /// <summary>End the connection.</summary>
    Disconnect,
}

/// <summary>The connection state that decides what may arrive next.</summary>
/// <param name="Role">Our side.</param>
/// <param name="Phase">The current phase.</param>
/// <param name="PeerKexRunning">The peer's KEXINIT has arrived and its NEWKEYS hasn't.</param>
/// <param name="StrictKex">Strict KEX is in force, which changes the rules during <see cref="TransportPhase.InitialKex"/>.</param>
/// <param name="FirstPacketAfterNewKeys">This is the first packet after the first NEWKEYS.</param>
/// <param name="SecondExtInfoAllowed">A client may still accept the one EXT_INFO allowed during auth.</param>
internal readonly record struct MessageContext(
    SshRole Role,
    TransportPhase Phase,
    bool PeerKexRunning,
    bool StrictKex,
    bool FirstPacketAfterNewKeys,
    bool SecondExtInfoAllowed);

/// <summary>
/// The single table of which messages are allowed when. Every incoming packet goes through it before
/// anything reads the message, and whatever it doesn't name is denied. Erlang CVE-2025-32433 and
/// CVE-2025-46712 were both a state machine that acted on a message it should have refused.
/// </summary>
internal static class MessagePolicy
{
    public static MessageDecision Evaluate(in MessageContext context, byte message)
    {
        bool strictInitial = context.StrictKex && context.Phase == TransportPhase.InitialKex;
        bool quiet = !context.PeerKexRunning;
        bool client = context.Role == SshRole.Client;
        bool server = !client;

        return message switch
        {
            MessageNumber.Disconnect => MessageDecision.Handle,
            // UNIMPLEMENTED may answer a global request, also during the peer's key exchange, by design: the peer may
            // be answering a request that reached it before our KEXINIT. The transport calls its handler only in
            // the Connected phase, so it can't reach anything while the user is still being authenticated.
            MessageNumber.Ignore or MessageNumber.Unimplemented or MessageNumber.Debug =>
                Allow(!strictInitial),
            MessageNumber.ServiceRequest => Allow(server && quiet && context.Phase == TransportPhase.AwaitService),
            MessageNumber.ServiceAccept => Allow(client && quiet && context.Phase == TransportPhase.AwaitService),
            MessageNumber.ExtInfo => Allow(quiet && (context.FirstPacketAfterNewKeys
                || (client && context.Phase == TransportPhase.Auth && context.SecondExtInfoAllowed))),
            MessageNumber.KexInit => Allow(quiet),
            MessageNumber.NewKeys or (>= 30 and <= 49) => Allow(context.PeerKexRunning),
            MessageNumber.UserAuthRequest => Allow(server && quiet && context.Phase == TransportPhase.Auth),
            MessageNumber.UserAuthFailure or MessageNumber.UserAuthSuccess or MessageNumber.UserAuthBanner =>
                Allow(client && quiet && context.Phase == TransportPhase.Auth),
            >= 60 and <= 79 => Allow(quiet && context.Phase == TransportPhase.Auth),
            >= 80 and <= 127 => Allow(quiet && context.Phase == TransportPhase.Connected),
            _ => strictInitial || context.PeerKexRunning ? MessageDecision.Disconnect : MessageDecision.Unimplemented,
        };
    }

    private static MessageDecision Allow(bool allowed) => allowed ? MessageDecision.Handle : MessageDecision.Disconnect;
}
