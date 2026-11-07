using System;
using Zorg.Ssh.AotSmoke;
using Zorg.Ssh.Protocol;

// Published with Native AOT and executed in CI. Trimming keeps only what's used, so every
// algorithm has to be exercised here: a clean publish alone proves little.
int failures = 0;

void Check(string name, bool ok)
{
    Console.WriteLine($"{(ok ? "ok  " : "FAIL")} {name}");
    if (!ok)
    {
        failures++;
    }
}

SshWriter writer = new();
writer.WriteNameList(["curve25519-sha256", "none"]);
SshReader reader = new(writer.Written);
Check("name-list round trip", reader.ReadNameList().Length == 2);
writer.Dispose();

CipherSmoke.Run(Check);
KeySmoke.Run(Check);
KeyFileSmoke.Run(Check);
await ConnectionSmoke.RunAsync(Check);
await LegacySmoke.RunAsync(Check);

return failures == 0 ? 0 : 1;
