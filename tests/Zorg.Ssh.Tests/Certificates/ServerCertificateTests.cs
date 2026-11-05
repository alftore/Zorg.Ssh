using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Auth;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Crypto.Keys;
using Zorg.Ssh.Transport;
using static Zorg.Ssh.Tests.Transport.TransportHarness;

namespace Zorg.Ssh.Tests.Certificates;

/// <summary>The server doesn't take certificates. That has to stay a failed attempt: not a dropped connection, and never a handler seeing a key it could mistake for a plain one.</summary>
public class ServerCertificateTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task A_certificate_is_a_failed_attempt_and_the_handler_never_sees_it()
    {
        using SshPrivateKey ca = SshPrivateKey.GenerateEd25519();
        SshPrivateKey user = SshPrivateKey.GenerateEd25519();
        SshCertificate certificate = new CertificateBuilder(user, ca) { Type = SshCertificate.UserType, Principals = ["alice"] }.Parse();
        int handled = 0;
        ServerAuthOptions options = new()
        {
            PublicKey = (_, _, _) =>
            {
                handled++;
                return ValueTask.FromResult(AuthDecision.Accept);
            },
            Password = (_, _, _) => ValueTask.FromResult(AuthDecision.Accept),
        };

        (SshTransport client, SshTransport server) = await ConnectAsync(ClientOptions(), ServerOptions(), Ct);
        await using (client)
        await using (server)
        {
            Task<AuthenticatedUser> serving = new ServerAuthenticator(server, options).AuthenticateAsync(Ct);
            SshCredential[] credentials =
            [
                new PrivateKeyCredential(() => new CertifiedPrivateKey(user, certificate), ownsKey: true),
                SshCredential.FromPassword("anything"),
            ];
            await new ClientAuthenticator(client, "alice", null).AuthenticateAsync(credentials, Ct);

            AuthenticatedUser who = await serving;
            Assert.Equal(["password"], who.Methods);
            Assert.Null(who.Key);
            Assert.Equal(0, handled);
        }
    }
}
