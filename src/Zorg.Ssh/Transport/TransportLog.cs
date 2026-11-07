using Microsoft.Extensions.Logging;

namespace Zorg.Ssh.Transport;

/// <summary>Transport log messages. Only algorithm names and counts appear here, never key material or payloads.</summary>
internal static partial class TransportLog
{
    [LoggerMessage(Level = LogLevel.Debug, Message = "Peer identified as {Identification}")]
    public static partial void PeerIdentified(ILogger logger, string identification);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Negotiated kex={Kex} hostkey={HostKey} send={SendCipher} mac={SendMac} receive={ReceiveCipher} mac={ReceiveMac} strict={Strict}")]
    public static partial void Negotiated(ILogger logger, string kex, string hostKey, string sendCipher, string sendMac, string receiveCipher, string receiveMac, bool strict);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Starting a rekey after {Bytes} bytes and {Packets} packets")]
    public static partial void RekeyStarting(ILogger logger, long bytes, long packets);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Key exchange finished")]
    public static partial void KexFinished(ILogger logger);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Transport failed")]
    public static partial void Failed(ILogger logger, System.Exception exception);
}
