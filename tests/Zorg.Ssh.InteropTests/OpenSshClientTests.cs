using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Protocol;
using Zorg.Ssh.Transport;

namespace Zorg.Ssh.InteropTests;

/// <summary>Real OpenSSH <c>ssh</c> against our server role (tier T1).</summary>
public class OpenSshClientTests
{
    private static readonly SshPrivateKey HostKey = SshPrivateKey.GenerateEd25519();

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public static TheoryData<string> Kex() => new(KeyExchangeCatalog.Default);

    public static TheoryData<string, string> Ciphers() => new()
    {
        { "aes256-gcm@openssh.com", "hmac-sha2-256-etm@openssh.com" },
        { "aes128-gcm@openssh.com", "hmac-sha2-256-etm@openssh.com" },
        { "chacha20-poly1305@openssh.com", "hmac-sha2-256-etm@openssh.com" },
        { "aes256-ctr", "hmac-sha2-512-etm@openssh.com" },
        { "aes256-ctr", "hmac-sha2-256-etm@openssh.com" },
        { "aes128-ctr", "hmac-sha2-512-etm@openssh.com" },
        { "aes128-ctr", "hmac-sha2-256-etm@openssh.com" },
    };

    [Theory]
    [MemberData(nameof(Kex))]
    public async Task Ssh_completes_each_key_exchange_with_our_server(string kex)
    {
        string log = await RunAsync(["-o", $"KexAlgorithms={kex}"]);
        Assert.Contains($"kex: algorithm: {kex}", log);
    }

    [Theory]
    [MemberData(nameof(Ciphers))]
    public async Task Ssh_talks_each_cipher_with_our_server(string cipher, string mac)
    {
        string log = await RunAsync(["-o", $"Ciphers={cipher}", "-o", $"MACs={mac}"]);
        Assert.Contains($"cipher: {cipher}", log);
    }

    [Fact]
    public async Task Ssh_negotiates_strict_KEX_with_our_server()
    {
        string log = await RunAsync([]);
        Assert.Contains("kex_choose_conf: will use strict KEX ordering", log, StringComparison.Ordinal);
    }

    /// <summary>
    /// Serves one connection as far as auth, where we refuse everything. Getting there proves key exchange,
    /// both ciphers and EXT_INFO: <c>ssh</c> sends SERVICE_REQUEST encrypted and reads our encrypted reply.
    /// </summary>
    private static async Task<string> RunAsync(string[] extraArguments)
    {
        string ssh = PeerTools.RequireSshClient();
        using TcpListener listener = new(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        Task serve = ServeOneAsync(listener);

        ProcessStartInfo start = new(ssh)
        {
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            RedirectStandardInput = true,
        };
        foreach (string argument in (string[])
            ["-vvv", "-F", "none", "-p", port.ToString(System.Globalization.CultureInfo.InvariantCulture),
             "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "BatchMode=yes",
             "-o", "PreferredAuthentications=none", "-o", "ConnectTimeout=15"])
        {
            start.ArgumentList.Add(argument);
        }

        foreach (string argument in extraArguments)
        {
            start.ArgumentList.Add(argument);
        }

        start.ArgumentList.Add("zorg@127.0.0.1");
        start.ArgumentList.Add("true");

        using Process process = Process.Start(start)!;
        process.StandardInput.Close();
        Task<string> output = process.StandardOutput.ReadToEndAsync(Ct);
        Task<string> error = process.StandardError.ReadToEndAsync(Ct);
        using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(30));
        await process.WaitForExitAsync(timeout.Token);
        string log = await error + await output;

        await serve.WaitAsync(TimeSpan.FromSeconds(10), Ct);
        Assert.Contains("Authentications that can continue: publickey", log, StringComparison.Ordinal);
        return log;
    }

    private static async Task ServeOneAsync(TcpListener listener)
    {
        using TcpClient socket = await listener.AcceptTcpClientAsync(Ct);
        await using SshTransport transport = await SshTransport.StartAsync(
            socket.GetStream(),
            new TransportOptions { Role = SshRole.Server, HostKeys = [HostKey] },
            Ct);

        ReadOnlyMemory<byte> request = await transport.ReceiveAsync(Ct);
        Assert.Equal(MessageNumber.ServiceRequest, request.Span[0]);
        await SendAsync(transport, static (ref SshWriter w) =>
        {
            w.WriteByte(MessageNumber.ServiceAccept);
            w.WriteUtf8String("ssh-userauth");
        });
        transport.SetPhase(TransportPhase.Auth);

        ReadOnlyMemory<byte> auth = await transport.ReceiveAsync(Ct);
        Assert.Equal(MessageNumber.UserAuthRequest, auth.Span[0]);
        await SendAsync(transport, static (ref SshWriter w) =>
        {
            w.WriteByte(MessageNumber.UserAuthFailure);
            w.WriteNameList(["publickey"]);
            w.WriteBoolean(false);
        });

        // ssh gives up here, and closing is the expected end.
        await Assert.ThrowsAnyAsync<SshConnectionException>(async () => await transport.ReceiveAsync(Ct));
    }

    private delegate void Build(ref SshWriter writer);

    private static async Task SendAsync(SshTransport transport, Build build)
    {
        System.Threading.Tasks.ValueTask send;
        SshWriter writer = new();
        try
        {
            build(ref writer);
            send = transport.SendAsync(writer.Written, Ct);
        }
        finally
        {
            writer.Dispose();
        }

        await send;
    }
}
