using System;
using System.Threading;
using System.Threading.Tasks;

namespace Zorg.Ssh.Examples;

/// <summary>The samples in docs/troubleshooting.md.</summary>
internal static class ErrorExamples
{
    public static async Task Catching(SshClientOptions options, CancellationToken cancellationToken)
    {
        // doc:errors
        try
        {
            await using SshClient client = await SshClient.ConnectAsync(options, cancellationToken);
            await client.ExecuteAsync("uptime", cancellationToken);
        }
        catch (SshHostKeyException ex)
        {
            // Never retry this one automatically. Show it to a person.
            Console.Error.WriteLine(ex.Message);
        }
        catch (SshAuthenticationException ex)
        {
            Console.Error.WriteLine($"Tried {string.Join(", ", ex.AttemptedMethods)}. The server accepts {string.Join(", ", ex.AllowedMethods)}.");
        }
        catch (SshNegotiationException ex)
        {
            Console.Error.WriteLine($"No common {ex.Family}. The server offers {string.Join(", ", ex.PeerAlgorithms)}.");
        }
        catch (SshDisconnectedException ex)
        {
            Console.Error.WriteLine($"The server hung up: {ex.Reason} {ex.Description}");
        }
        catch (SshConnectionException ex)
        {
            Console.Error.WriteLine($"Network failure, safe to reconnect: {ex.Message}");
        }
        catch (SshException ex)
        {
            Console.Error.WriteLine(ex.Message);
        }
        // end-doc
    }
}
