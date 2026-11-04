using System.Threading;
using System.Threading.Tasks;

namespace Zorg.Ssh.Transport;

/// <summary>Small services the layers above need from the transport.</summary>
internal sealed partial class SshTransport
{
    /// <summary>Replies UNIMPLEMENTED to the packet just returned by <see cref="ReceiveAsync"/>.</summary>
    public ValueTask SendUnimplementedForLastPacketAsync(CancellationToken cancellationToken) =>
        SendUnimplementedAsync(_lastReceivedSequence, cancellationToken);
}
