using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Auth;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Crypto.Keys;
using Zorg.Ssh.Protocol;
using Zorg.Ssh.Tests.Fuzzing.Stateful;
using Zorg.Ssh.Transport;
using Zorg.Ssh.Tests.Transport;

namespace Zorg.Ssh.Tests.Server;

/// <summary>
/// <see cref="SshAlgorithms.LegacyUnsafe"/>: what it adds, what it never adds, who may name its algorithms, the server's
/// explicit-only Diffie-Hellman, the warning, and <c>ssh-rsa</c> (SHA-1) for host keys and user signatures.
/// </summary>
public sealed class LegacyAlgorithmTests : IDisposable
{
    private static readonly SshPrivateKey RsaKey = SshPrivateKey.GenerateRsa(2048);

    private readonly SshHostKey _ed25519 = SshHostKey.GenerateEd25519();

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose() => _ed25519.Dispose();

    [Fact]
    public void LegacyUnsafe_is_the_defaults_with_the_legacy_names_appended()
    {
        SshAlgorithms legacy = SshAlgorithms.LegacyUnsafe;
        SshAlgorithms defaults = SshAlgorithms.Default;

        Assert.Equal([.. defaults.KeyExchange, "diffie-hellman-group14-sha256", "diffie-hellman-group16-sha512", "diffie-hellman-group14-sha1"], legacy.KeyExchange);
        Assert.Equal([.. defaults.HostKeys, "ssh-rsa"], legacy.HostKeys);
        Assert.Equal(defaults.Ciphers, legacy.Ciphers);
        Assert.Equal([.. defaults.Macs, "hmac-sha1-etm@openssh.com", "hmac-sha1"], legacy.Macs);
        Assert.Same(legacy, SshAlgorithms.LegacyUnsafe);
        legacy.Validate();
    }

    [Fact]
    public void The_defaults_hold_no_legacy_name()
    {
        SshAlgorithms defaults = SshAlgorithms.Default;
        string[] all = [.. defaults.KeyExchange, .. defaults.HostKeys, .. defaults.Ciphers, .. defaults.Macs];

        Assert.DoesNotContain(all, LegacyAlgorithms.IsLegacy);
        Assert.False(defaults.AllowsRsaSha1);
        Assert.Null(defaults.KeyExchangeExtension);
    }

    [Theory]
    [InlineData("KeyExchange", "diffie-hellman-group14-sha256")]
    [InlineData("KeyExchange", "diffie-hellman-group16-sha512")]
    [InlineData("KeyExchange", "diffie-hellman-group14-sha1")]
    [InlineData("HostKeys", "ssh-rsa")]
    [InlineData("Macs", "hmac-sha1")]
    [InlineData("Macs", "hmac-sha1-etm@openssh.com")]
    public void A_legacy_name_may_be_named_explicitly(string family, string name) => Build(family, name).Validate();

    [Theory]
    [InlineData("KeyExchange", "diffie-hellman-group1-sha1")]
    [InlineData("KeyExchange", "diffie-hellman-group-exchange-sha256")]
    [InlineData("KeyExchange", "diffie-hellman-group-exchange-sha1")]
    [InlineData("KeyExchange", "diffie-hellman-group18-sha512")]
    [InlineData("HostKeys", "ssh-dss")]
    [InlineData("HostKeys", "ssh-rsa-cert-v01@openssh.com")]
    [InlineData("Ciphers", "3des-cbc")]
    [InlineData("Ciphers", "aes128-cbc")]
    [InlineData("Ciphers", "arcfour")]
    [InlineData("Macs", "hmac-md5")]
    [InlineData("Macs", "hmac-sha1-96")]
    [InlineData("Macs", "HMAC-SHA1")]
    public void Never_supported_names_are_refused_and_the_message_points_at_LegacyUnsafe(string family, string name)
    {
        ArgumentException failure = Assert.Throws<ArgumentException>(() => Build(family, name).Validate());

        Assert.Contains($"'{name}'", failure.Message, StringComparison.Ordinal);
        if (family != "Ciphers")
        {
            Assert.Contains("LegacyUnsafe adds", failure.Message, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Only_an_explicit_key_exchange_list_or_the_preset_can_reach_finite_field_code()
    {
        Assert.Null(new SshAlgorithms { Ciphers = ["aes128-ctr"] }.KeyExchangeExtension);
        Assert.NotNull(new SshAlgorithms { KeyExchange = ["curve25519-sha256"] }.KeyExchangeExtension);
        Assert.NotNull(SshAlgorithms.LegacyUnsafe.KeyExchangeExtension);
        Assert.False(SshAlgorithms.LegacyUnsafe.KeyExchangeIsExplicit);
    }

    [Fact]
    public void A_server_offers_Diffie_Hellman_only_when_its_list_names_it()
    {
        Assert.DoesNotContain(SshAlgorithms.LegacyUnsafe.ServerKeyExchange, LegacyAlgorithms.IsFiniteFieldDh);
        Assert.Equal(KeyExchangeCatalog.Default, SshAlgorithms.LegacyUnsafe.ServerKeyExchange);
        Assert.Equal(["diffie-hellman-group14-sha1"], new SshAlgorithms { KeyExchange = ["diffie-hellman-group14-sha1"] }.ServerKeyExchange);
    }

    [Fact]
    public async Task A_legacy_client_against_a_modern_server_uses_modern_algorithms_and_warns_of_nothing()
    {
        CaptureLoggerFactory logs = new();
        await using SshServer server = await StartAsync(SshAlgorithms.Default, _ed25519);
        await using SshClient client = await SshClient.ConnectAsync(ClientOptions(server, _ed25519, SshAlgorithms.LegacyUnsafe, logs), Ct);

        Assert.Equal(0, (await client.ExecuteAsync("x", Ct)).ExitCode);
        Assert.DoesNotContain(logs.Entries, line => line.StartsWith("[Warning]", StringComparison.Ordinal));
        Assert.DoesNotContain(logs.Entries, line => LegacyAlgorithms.KeyExchange.Concat(LegacyAlgorithms.Macs).Any(name => line.Contains(name, StringComparison.Ordinal)));
    }

    [Theory]
    [InlineData("diffie-hellman-group14-sha256")]
    [InlineData("diffie-hellman-group16-sha512")]
    [InlineData("diffie-hellman-group14-sha1")]
    public async Task A_legacy_client_logs_in_to_a_server_that_names_Diffie_Hellman_and_warns(string kex)
    {
        CaptureLoggerFactory logs = new();
        await using SshServer server = await StartAsync(new SshAlgorithms { KeyExchange = [kex] }, _ed25519);
        await using SshClient client = await SshClient.ConnectAsync(ClientOptions(server, _ed25519, SshAlgorithms.LegacyUnsafe, logs), Ct);

        Assert.Equal(0, (await client.ExecuteAsync("x", Ct)).ExitCode);
        Assert.Contains(logs.Entries, line => line.StartsWith("[Warning]", StringComparison.Ordinal) && line.Contains($"legacy algorithm {kex}", StringComparison.Ordinal));
        Assert.Contains(logs.Entries, line => line.Contains($"kex={kex}", StringComparison.Ordinal) && line.Contains("strict=True", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_server_on_the_preset_doesnt_offer_Diffie_Hellman()
    {
        await using SshServer server = await StartAsync(SshAlgorithms.LegacyUnsafe, _ed25519);
        SshNegotiationException failure = await Assert.ThrowsAsync<SshNegotiationException>(
            () => SshClient.ConnectAsync(ClientOptions(server, _ed25519, new SshAlgorithms { KeyExchange = ["diffie-hellman-group14-sha256"] }), Ct));

        Assert.Equal("key exchange", failure.Family);
        Assert.DoesNotContain(failure.PeerAlgorithms, LegacyAlgorithms.IsFiniteFieldDh);
    }

    [Fact]
    public async Task A_default_client_against_a_legacy_only_server_is_told_about_LegacyUnsafe()
    {
        await using SshServer server = await StartAsync(new SshAlgorithms { KeyExchange = ["diffie-hellman-group14-sha1"] }, _ed25519);
        SshNegotiationException failure = await Assert.ThrowsAsync<SshNegotiationException>(
            () => SshClient.ConnectAsync(ClientOptions(server, _ed25519, SshAlgorithms.Default), Ct));

        Assert.Contains("diffie-hellman-group14-sha1, which SshAlgorithms.LegacyUnsafe enables", failure.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("hmac-sha1")]
    [InlineData("hmac-sha1-etm@openssh.com")]
    public async Task The_SHA_1_MACs_carry_a_session_and_warn(string mac)
    {
        CaptureLoggerFactory logs = new();
        await using SshServer server = await StartAsync(new SshAlgorithms { Ciphers = ["aes128-ctr"], Macs = [mac] }, _ed25519);
        await using SshClient client = await SshClient.ConnectAsync(ClientOptions(server, _ed25519, SshAlgorithms.LegacyUnsafe, logs), Ct);

        client.RequestRekey();
        Assert.Equal(0, (await client.ExecuteAsync("x", Ct)).ExitCode);
        Assert.Contains(logs.Entries, line => line.Contains($"mac={mac}", StringComparison.Ordinal));
        Assert.Contains(logs.Entries, line => line.StartsWith("[Warning]", StringComparison.Ordinal) && line.Contains(mac, StringComparison.Ordinal));
    }

    [Fact]
    public async Task An_ssh_rsa_host_key_works_only_for_a_client_that_allows_it()
    {
        using SshHostKey rsa = new(SshPrivateKey.GenerateRsa(2048));
        await using SshServer server = await StartAsync(new SshAlgorithms { HostKeys = ["ssh-rsa"] }, rsa);

        SshNegotiationException refused = await Assert.ThrowsAsync<SshNegotiationException>(
            () => SshClient.ConnectAsync(ClientOptions(server, rsa, SshAlgorithms.Default), Ct));
        Assert.Contains("ssh-rsa, which SshAlgorithms.LegacyUnsafe enables", refused.Message, StringComparison.Ordinal);

        CaptureLoggerFactory logs = new();
        await using SshClient client = await SshClient.ConnectAsync(ClientOptions(server, rsa, SshAlgorithms.LegacyUnsafe, logs), Ct);
        Assert.Equal(0, (await client.ExecuteAsync("x", Ct)).ExitCode);
        Assert.Contains(logs.Entries, line => line.Contains("hostkey=ssh-rsa ", StringComparison.Ordinal));
        Assert.Contains(logs.Entries, line => line.StartsWith("[Warning]", StringComparison.Ordinal) && line.Contains("ssh-rsa", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_legacy_server_with_an_RSA_key_still_prefers_SHA_2_with_a_modern_client()
    {
        using SshHostKey rsa = new(SshPrivateKey.GenerateRsa(2048));
        CaptureLoggerFactory logs = new();
        await using SshServer server = await StartAsync(SshAlgorithms.LegacyUnsafe, rsa);
        await using SshClient client = await SshClient.ConnectAsync(ClientOptions(server, rsa, SshAlgorithms.LegacyUnsafe, logs), Ct);

        Assert.Equal(0, (await client.ExecuteAsync("x", Ct)).ExitCode);
        Assert.Contains(logs.Entries, line => line.Contains("hostkey=rsa-sha2-512 ", StringComparison.Ordinal));
    }

    [Fact]
    public void The_generic_RSA_path_never_takes_SHA_1_so_CA_signatures_stay_refused()
    {
        RsaPublicKey key = (RsaPublicKey)RsaKey.PublicKey;
        byte[] data = "signed"u8.ToArray();
        byte[] sha1 = LegacyRsa.Sign(RsaKey, data);

        Assert.True(LegacyRsa.Verify(key, data, sha1));
        Assert.False(key.SupportsSignatureAlgorithm("ssh-rsa"));
        Assert.False(key.Verify("ssh-rsa", data, sha1));
        Assert.DoesNotContain("ssh-rsa", RsaKey.SignatureAlgorithms);
        Assert.Throws<ArgumentException>(() => RsaKey.Sign("ssh-rsa", data));
        Assert.Null(SshCertificate.PlainSignatureAlgorithm("ssh-rsa-cert-v01@openssh.com"));

        // A SHA-2 signature isn't a SHA-1 one, and a tampered SHA-1 one fails.
        Assert.False(LegacyRsa.Verify(key, data, RsaKey.Sign("rsa-sha2-256", data)));
        sha1[^1] ^= 1;
        Assert.False(LegacyRsa.Verify(key, data, sha1));
        Assert.False(LegacyRsa.Verify(SshPrivateKey.GenerateEd25519().PublicKey, data, sha1));
    }

    [Fact]
    public void A_platform_refusal_of_SHA_1_says_so()
    {
        SshNegotiationException failure = LegacyRsa.PolicyRefusal(new CryptographicException("policy"));

        Assert.Contains("ssh-rsa", failure.Message, StringComparison.Ordinal);
        Assert.Contains("crypto policy", failure.Message, StringComparison.Ordinal);
        Assert.Contains("update-crypto-policies", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void The_SHA_1_probe_agrees_with_what_the_platform_does()
    {
        bool signs;
        try
        {
#pragma warning disable CA5350 // Legacy ssh-rsa, in a test.
            signs = LegacyRsa.Sign(RsaKey, [1]).Length > 0;
#pragma warning restore CA5350
        }
        catch (SshNegotiationException)
        {
            signs = false;
        }

        Assert.Equal(signs, LegacyRsa.PlatformAllowsSha1);
        Assert.Equal(signs, LegacyRsa.ProbeSha1());
    }

    [Fact]
    public void A_bad_signature_or_the_wrong_one_is_false_even_where_the_platform_forbids_SHA_1()
    {
        // The policy message belongs to the platform, so a peer's bytes alone must not be able to cause it.
        LegacyRsa.SetPlatformAllowsSha1ForTests(false);
        try
        {
            SshPublicKey key = RsaKey.PublicKey;
            byte[] data = [1, 2, 3];
            Assert.False(LegacyRsa.Verify(key, data, []));
            Assert.False(LegacyRsa.Verify(key, data, new byte[64]));
            Assert.False(LegacyRsa.Verify(key, data, RsaKey.Sign("rsa-sha2-256", data)));
        }
        finally
        {
            LegacyRsa.SetPlatformAllowsSha1ForTests(null);
        }
    }

    public static TheoryData<string?, bool, string> SignatureChoices => new()
    {
        { null, false, "rsa-sha2-512" }, // no server-sig-algs, legacy off: today's behaviour
        { null, true, "ssh-rsa" }, // no server-sig-algs, legacy on: as OpenSSH does
        { "rsa-sha2-256,ssh-rsa", true, "rsa-sha2-256" },
        { "ssh-rsa", true, "ssh-rsa" },
        { "ssh-rsa", false, "rsa-sha2-512" },
        { "ssh-ed25519", true, "rsa-sha2-512" },
    };

    [Theory]
    [MemberData(nameof(SignatureChoices))]
    public void The_client_picks_ssh_rsa_only_with_legacy_on_and_no_better_choice(string? serverSigAlgs, bool rsaSha1, string expected)
    {
        Dictionary<string, byte[]> extensions = serverSigAlgs is null ? [] : new() { ["server-sig-algs"] = Encoding.ASCII.GetBytes(serverSigAlgs) };

        Assert.Equal(expected, ClientAuthenticator.SignatureAlgorithmFor(RsaKey.SignatureAlgorithms, extensions, rsaSha1));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task The_server_takes_an_ssh_rsa_user_signature_only_when_allowed(bool allowed)
    {
        (SshTransport client, SshTransport server) = await TransportHarness.ConnectAsync(TransportHarness.ClientOptions(), TransportHarness.ServerOptions(), Ct);
        await using (client)
        await using (server)
        {
            ServerAuthOptions options = new() { PublicKey = (_, _, _) => ValueTask.FromResult(AuthDecision.Accept), AllowRsaSha1 = allowed };
            Task<AuthenticatedUser> auth = new ServerAuthenticator(server, options).AuthenticateAsync(Ct);
            await client.SendAsync(Request(w =>
            {
                w.Byte(MessageNumber.ServiceRequest);
                w.String("ssh-userauth");
            }), Ct);
            client.SetPhase(TransportPhase.AwaitService);
            Assert.Equal(MessageNumber.ServiceAccept, (await client.ReceiveAsync(Ct)).Span[0]);
            client.SetPhase(TransportPhase.Auth);

            await client.SendAsync(SignedSha1Request(client), Ct);
            ReadOnlyMemory<byte> reply = await client.ReceiveAsync(Ct);
            if (allowed)
            {
                Assert.Equal(MessageNumber.UserAuthSuccess, reply.Span[0]);
                Assert.Equal(RsaKey.PublicKey.Blob.ToArray(), (await auth).Key!.Blob.ToArray());
            }
            else
            {
                Assert.Equal(MessageNumber.UserAuthFailure, reply.Span[0]);
            }
        }
    }

    [Fact]
    public async Task A_legacy_client_logs_in_to_a_legacy_server_with_an_RSA_key()
    {
        using SshHostKey host = new(SshPrivateKey.GenerateEd25519());
        List<string> keyTypes = [];
        SshServerOptions options = new()
        {
            HostKeys = [host],
            Algorithms = SshAlgorithms.LegacyUnsafe,
            PublicKeyHandler = (request, _) =>
            {
                lock (keyTypes)
                {
                    keyTypes.Add(request.KeyType);
                }

                return ValueTask.FromResult(SshAuthDecision.Accept);
            },
            SessionHandler = (_, _) => Task.FromResult(0),
        };
        await using SshServer server = await SshServer.StartAsync(options, Ct);
        await using SshClient connected = await SshClient.ConnectAsync(
            new SshClientOptions
            {
                Host = "127.0.0.1",
                Port = server.LocalEndPoint.Port,
                UserName = "alice",
                HostKeyPolicy = HostKeyPolicy.Fingerprint(host.Sha256Fingerprint),
                Algorithms = SshAlgorithms.LegacyUnsafe,
                Credentials = [new PrivateKeyCredential(() => RsaKey, ownsKey: false)],
            },
            Ct);

        Assert.Equal(0, (await connected.ExecuteAsync("x", Ct)).ExitCode);
        Assert.Contains("ssh-rsa", keyTypes);
    }

    private static byte[] SignedSha1Request(SshTransport client)
    {
        byte[] blob = RsaKey.PublicKey.Blob.ToArray();
        SshWriter signed = new(1024);
        byte[] data;
        try
        {
            signed.WriteBinary(client.SessionId.Span);
            signed.WriteByte(MessageNumber.UserAuthRequest);
            signed.WriteUtf8String("alice");
            signed.WriteUtf8String("ssh-connection");
            signed.WriteUtf8String("publickey");
            signed.WriteBoolean(true);
            signed.WriteUtf8String("ssh-rsa");
            signed.WriteBinary(blob);
            data = signed.ToArray();
        }
        finally
        {
            signed.Dispose();
        }

        byte[] signature = LegacyRsa.Sign(RsaKey, data);
        return Request(w =>
        {
            w.Byte(MessageNumber.UserAuthRequest);
            w.String("alice");
            w.String("ssh-connection");
            w.String("publickey");
            w.Bool(true);
            w.String("ssh-rsa");
            w.Bytes(blob);
            w.Bytes(signature);
        });
    }

    private static byte[] Request(Action<SshRequestWriter> build)
    {
        SshRequestWriter writer = new();
        build(writer);
        return writer.ToArray();
    }

    private static SshAlgorithms Build(string family, string name) => family switch
    {
        "KeyExchange" => new SshAlgorithms { KeyExchange = [name] },
        "HostKeys" => new SshAlgorithms { HostKeys = [name] },
        "Ciphers" => new SshAlgorithms { Ciphers = [name] },
        _ => new SshAlgorithms { Macs = [name] },
    };

    private static Task<SshServer> StartAsync(SshAlgorithms algorithms, SshHostKey hostKey) => SshServer.StartAsync(
        new SshServerOptions
        {
            HostKeys = [hostKey],
            Algorithms = algorithms,
            PasswordHandler = (_, _) => ValueTask.FromResult(SshAuthDecision.Accept),
            SessionHandler = (_, _) => Task.FromResult(0),
        },
        Ct);

    private static SshClientOptions ClientOptions(SshServer server, SshHostKey hostKey, SshAlgorithms algorithms, CaptureLoggerFactory? logs = null) => new()
    {
        Host = "127.0.0.1",
        Port = server.LocalEndPoint.Port,
        UserName = "alice",
        Credentials = [SshCredential.FromPassword("pw")],
        HostKeyPolicy = HostKeyPolicy.Fingerprint(hostKey.Sha256Fingerprint),
        Algorithms = algorithms,
        LoggerFactory = logs,
    };
}
