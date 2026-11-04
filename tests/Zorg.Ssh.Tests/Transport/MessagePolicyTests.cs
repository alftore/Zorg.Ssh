using System;
using Xunit;
using Zorg.Ssh.Protocol;
using Zorg.Ssh.Transport;

namespace Zorg.Ssh.Tests.Transport;

public class MessagePolicyTests
{
    private static MessageDecision Check(
        SshRole role,
        TransportPhase phase,
        byte message,
        bool peerKex = false,
        bool strict = false,
        bool firstAfterNewKeys = false,
        bool secondExtInfo = false) =>
        MessagePolicy.Evaluate(new MessageContext(role, phase, peerKex, strict, firstAfterNewKeys, secondExtInfo), message);

    // Erlang CVE-2025-32433: connection messages before auth were acted on, giving remote code execution.
    [Theory]
    [InlineData((int)TransportPhase.InitialKex)]
    [InlineData((int)TransportPhase.AwaitService)]
    [InlineData((int)TransportPhase.Auth)]
    public void Connection_messages_before_auth_end_the_connection(int phaseValue)
    {
        TransportPhase phase = (TransportPhase)phaseValue;
        for (int message = 80; message <= 127; message++)
        {
            Assert.Equal(MessageDecision.Disconnect, Check(SshRole.Server, phase, (byte)message));
            Assert.Equal(MessageDecision.Disconnect, Check(SshRole.Client, phase, (byte)message));
        }
    }

    // Erlang CVE-2025-46712: optional messages slipped through a strict initial KEX.
    [Theory]
    [InlineData(MessageNumber.Ignore)]
    [InlineData(MessageNumber.Debug)]
    [InlineData(MessageNumber.Unimplemented)]
    [InlineData(MessageNumber.ExtInfo)]
    [InlineData(MessageNumber.ServiceRequest)]
    [InlineData(100)]
    [InlineData(200)]
    public void Optional_messages_under_strict_KEX_end_the_connection(byte message)
    {
        Assert.Equal(MessageDecision.Disconnect, Check(SshRole.Client, TransportPhase.InitialKex, message, strict: true));
        Assert.Equal(MessageDecision.Disconnect, Check(SshRole.Server, TransportPhase.InitialKex, message, peerKex: true, strict: true));
    }

    [Theory]
    [InlineData(MessageNumber.Ignore)]
    [InlineData(MessageNumber.Debug)]
    public void Optional_messages_stay_legal_during_a_strict_rekey(byte message) =>
        Assert.Equal(MessageDecision.Handle, Check(SshRole.Client, TransportPhase.Connected, message, peerKex: true, strict: true));

    [Fact]
    public void Disconnect_is_always_handled()
    {
        foreach (TransportPhase phase in Enum.GetValues<TransportPhase>())
        {
            Assert.Equal(MessageDecision.Handle, Check(SshRole.Server, phase, MessageNumber.Disconnect, peerKex: true, strict: true));
        }
    }

    [Theory]
    [InlineData(MessageNumber.ChannelData)]
    [InlineData(MessageNumber.GlobalRequest)]
    [InlineData(MessageNumber.UserAuthRequest)]
    [InlineData(MessageNumber.ServiceRequest)]
    public void Non_KEX_messages_after_the_peers_KEXINIT_end_the_connection(byte message) =>
        Assert.Equal(MessageDecision.Disconnect, Check(SshRole.Server, TransportPhase.Connected, message, peerKex: true));

    [Fact]
    public void Peer_may_send_data_until_its_own_KEXINIT() =>
        Assert.Equal(MessageDecision.Handle, Check(SshRole.Server, TransportPhase.Connected, MessageNumber.ChannelData));

    [Fact]
    public void A_second_KEXINIT_during_an_exchange_ends_the_connection() =>
        Assert.Equal(MessageDecision.Disconnect, Check(SshRole.Client, TransportPhase.Connected, MessageNumber.KexInit, peerKex: true));

    [Theory]
    [InlineData(MessageNumber.NewKeys)]
    [InlineData(MessageNumber.KexEcdhInit)]
    [InlineData(MessageNumber.KexEcdhReply)]
    [InlineData(49)]
    public void KEX_messages_outside_an_exchange_end_the_connection(byte message)
    {
        Assert.Equal(MessageDecision.Disconnect, Check(SshRole.Server, TransportPhase.Connected, message));
        Assert.Equal(MessageDecision.Disconnect, Check(SshRole.Client, TransportPhase.InitialKex, message));
    }

    // AsyncSSH CVE-2023-46445 and CVE-2023-46446: auth and EXT_INFO ordering could be manipulated.
    [Fact]
    public void Auth_messages_only_flow_the_right_way_in_the_auth_phase()
    {
        Assert.Equal(MessageDecision.Handle, Check(SshRole.Server, TransportPhase.Auth, MessageNumber.UserAuthRequest));
        Assert.Equal(MessageDecision.Disconnect, Check(SshRole.Client, TransportPhase.Auth, MessageNumber.UserAuthRequest));
        Assert.Equal(MessageDecision.Handle, Check(SshRole.Client, TransportPhase.Auth, MessageNumber.UserAuthSuccess));
        Assert.Equal(MessageDecision.Disconnect, Check(SshRole.Server, TransportPhase.Auth, MessageNumber.UserAuthSuccess));
        Assert.Equal(MessageDecision.Disconnect, Check(SshRole.Client, TransportPhase.AwaitService, MessageNumber.UserAuthSuccess));
        Assert.Equal(MessageDecision.Disconnect, Check(SshRole.Client, TransportPhase.Connected, MessageNumber.UserAuthSuccess));
        Assert.Equal(MessageDecision.Disconnect, Check(SshRole.Server, TransportPhase.Connected, MessageNumber.UserAuthRequest));
    }

    [Fact]
    public void Ext_info_is_only_legal_where_RFC_8308_puts_it()
    {
        Assert.Equal(MessageDecision.Handle, Check(SshRole.Client, TransportPhase.AwaitService, MessageNumber.ExtInfo, firstAfterNewKeys: true));
        Assert.Equal(MessageDecision.Handle, Check(SshRole.Server, TransportPhase.AwaitService, MessageNumber.ExtInfo, firstAfterNewKeys: true));
        Assert.Equal(MessageDecision.Disconnect, Check(SshRole.Client, TransportPhase.AwaitService, MessageNumber.ExtInfo));
        Assert.Equal(MessageDecision.Handle, Check(SshRole.Client, TransportPhase.Auth, MessageNumber.ExtInfo, secondExtInfo: true));
        Assert.Equal(MessageDecision.Disconnect, Check(SshRole.Client, TransportPhase.Auth, MessageNumber.ExtInfo));
        Assert.Equal(MessageDecision.Disconnect, Check(SshRole.Server, TransportPhase.Auth, MessageNumber.ExtInfo, secondExtInfo: true));
        Assert.Equal(MessageDecision.Disconnect, Check(SshRole.Client, TransportPhase.Connected, MessageNumber.ExtInfo));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(8)]
    [InlineData(19)]
    [InlineData(22)]
    [InlineData(29)]
    [InlineData(54)]
    [InlineData(128)]
    [InlineData(255)]
    public void Unassigned_numbers_get_unimplemented_outside_KEX(byte message)
    {
        Assert.Equal(MessageDecision.Unimplemented, Check(SshRole.Client, TransportPhase.Connected, message));
        Assert.Equal(MessageDecision.Disconnect, Check(SshRole.Client, TransportPhase.Connected, message, peerKex: true));
    }
}
