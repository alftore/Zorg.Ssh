using System;
using System.Collections.Generic;
using System.Linq;

namespace Zorg.Ssh.Tests.Fuzzing.Stateful;

/// <summary>
/// Changes a valid message sequence the way a hostile peer would: bytes inside a message (through <see cref="FuzzMutator"/>, which
/// knows where length fields are), and also whole messages. It reorders them, replays them later, drops them, retypes them,
/// floods one, and slips in messages that belong to another phase. The sequence stays mostly valid, so that an input reaches
/// deep states instead of dying on its first packet.
/// </summary>
internal static class SequenceMutator
{
    private static readonly byte[] AllNumbers = [.. Enumerable.Range(1, 127).Select(n => (byte)n), 128, 200, 250, 255];

    public static List<FuzzOp> Mutate(FuzzRandom random, IReadOnlyList<FuzzOp> valid, IReadOnlyList<FuzzOp> pool)
    {
        List<FuzzOp> ops = [.. valid];
        if (random.Chance(4))
        {
            return ops;
        }

        int changes = 1 + random.Next(3);
        if (random.Chance(15))
        {
            changes += random.Next(6);
        }

        for (int i = 0; i < changes && ops.Count > 0; i++)
        {
            Apply(random, ops, pool);
            if (ops.Count > FuzzOpCodec.MaxOps)
            {
                ops.RemoveRange(FuzzOpCodec.MaxOps, ops.Count - FuzzOpCodec.MaxOps);
            }
        }

        return ops;
    }

    private static void Apply(FuzzRandom random, List<FuzzOp> ops, IReadOnlyList<FuzzOp> pool)
    {
        int roll = random.Next(100);
        int index = random.Next(ops.Count);
        switch (roll)
        {
            case < 34:
                ByteMutate(random, ops, index);
                break;
            case < 43:
                ops.RemoveAt(index);
                break;
            case < 55:
                Replay(random, ops, index);
                break;
            case < 67:
                Reorder(random, ops, index);
                break;
            case < 79 when pool.Count > 0:
                ops.Insert(random.Next(ops.Count + 1), pool[random.Next(pool.Count)]);
                break;
            case < 83:
                ops.Insert(random.Next(ops.Count + 1), FuzzOp.Send([AllNumbers[random.Next(AllNumbers.Length)], .. Noise(random, random.Next(41))]));
                break;
            case < 91:
                Retype(random, ops, index);
                break;
            case < 96:
                Flood(random, ops, index);
                break;
            case < 99:
                ops.RemoveRange(index, ops.Count - index);
                break;
            default:
                ops.Insert(random.Next(ops.Count + 1), FuzzOp.Of(OpKind.Disconnect));
                break;
        }
    }

    private static void ByteMutate(FuzzRandom random, List<FuzzOp> ops, int index)
    {
        FuzzOp op = ops[index];
        if (op.Kind is OpKind.Await or OpKind.Rekey or OpKind.Pause or OpKind.Disconnect or OpKind.KexCanary or OpKind.SutRekey || op.Body.Length == 0)
        {
            return;
        }

        List<FuzzSeed> siblings = [.. ops.Where(o => o.Kind == op.Kind && o.Body.Length > 0).Take(8).Select(o => FuzzSeed.Binary(o.Kind.ToString(), o.Body))];
        FuzzSeed seed = FuzzSeed.Binary(op.Kind.ToString(), op.Body);
        byte[] changed = FuzzMutator.MutateBinary(random, seed, siblings);
        if (op.Kind is OpKind.App or OpKind.SftpRespond && changed.Length == 0)
        {
            return;
        }

        ops[index] = op with { Body = changed.Length > FuzzOpCodec.MaxBody ? changed[..FuzzOpCodec.MaxBody] : changed };
    }

    private static void Replay(FuzzRandom random, List<FuzzOp> ops, int index)
    {
        FuzzOp op = ops[index];
        int copies = 1 + (random.Chance(20) ? random.Next(3) : 0);
        int at = Math.Min(ops.Count, index + random.Next(ops.Count - index + 1));
        for (int i = 0; i < copies; i++)
        {
            ops.Insert(at, op);
        }
    }

    private static void Reorder(FuzzRandom random, List<FuzzOp> ops, int index)
    {
        FuzzOp op = ops[index];
        ops.RemoveAt(index);
        int to = random.Chance(60) ? Math.Clamp(index + (random.Chance(50) ? 1 : -1), 0, ops.Count) : random.Next(ops.Count + 1);
        ops.Insert(to, op);
    }

    private static void Retype(FuzzRandom random, List<FuzzOp> ops, int index)
    {
        FuzzOp op = ops[index];
        if (op.Kind != OpKind.Send || op.Body.Length == 0)
        {
            return;
        }

        byte[] body = [.. op.Body];
        body[0] = AllNumbers[random.Next(AllNumbers.Length)];
        ops[index] = op with { Body = body };
    }

    private static void Flood(FuzzRandom random, List<FuzzOp> ops, int index)
    {
        FuzzOp op = ops[index];
        if (op.Kind is OpKind.Await or OpKind.Disconnect or OpKind.Rekey)
        {
            return;
        }

        int count = random.Pick<int>([8, 20, 70, 150, 300]);
        count = Math.Min(count, FuzzOpCodec.MaxOps - ops.Count);
        ops.InsertRange(index, Enumerable.Repeat(op, Math.Max(0, count)));
    }

    private static byte[] Noise(FuzzRandom random, int count)
    {
        byte[] bytes = new byte[count];
        for (int i = 0; i < count; i++)
        {
            bytes[i] = random.NextByte();
        }

        return bytes;
    }
}
