// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using PasswordManagerAccess.Common;
using R = PasswordManagerAccess.OnePassword.Response;

namespace PasswordManagerAccess.OnePassword;

internal static class SrpV2
{
    public static AesKey PerformAndVerify(Credentials credentials, SrpInfo srpInfo, string keyUuid, string sessionId, RestClient rest)
    {
        var key = Perform(Srp.GenerateSecretA(), credentials, srpInfo, keyUuid, rest);
        return new AesKey(sessionId, key);
    }

    //
    // Internal
    //

    internal static byte[] Perform(BigInteger secretA, Credentials credentials, SrpInfo srpInfo, string keyUuid, RestClient rest)
    {
        var sharedA = Srp.ComputeSharedA(secretA);
        var sharedB = ExchangeAForB(sharedA, rest);
        Srp.ValidateB(sharedB);

        var sessionKey = ComputeKey(secretA, sharedA, sharedB, credentials.SrpX.DecodeHex());
        VerifyKey(sessionKey, credentials.Username, keyUuid, srpInfo.Salt, sharedA, sharedB, rest);

        return sessionKey;
    }

    internal static BigInteger ExchangeAForB(BigInteger sharedA, RestClient rest)
    {
        var response = rest.PostJson<R.AForBV2>("v2/auth", new Dictionary<string, object> { ["userA"] = sharedA.ToHex() });

        // TODO: Do we need better error handling here?
        if (!response.IsSuccessful)
            throw new InternalErrorException($"Request to {response.RequestUri} failed");

        return response.Data.B.ToBigInt();
    }

    internal static byte[] ComputeKey(BigInteger secretA, BigInteger sharedA, BigInteger sharedB, byte[] srpX)
    {
        // Always "3509477ea9fca66eadb7cf7b1bd0eb508f54d3989a9c988006a7d0b338374dd2"
        var gModN = Crypto.Sha256(ToCompatibleByteArray(Srp.SirpN).Concat(ModBytes(Srp.SirpG, Srp.SirpN)).ToArray());

        var aModN = ModBytes(sharedA, Srp.SirpN);
        var bModN = ModBytes(sharedB, Srp.SirpN);
        var abSha256 = Crypto.Sha256(aModN.Concat(bModN).ToArray());

        var x = srpX.ToBigInt();
        var o = secretA + abSha256.ToBigInt() * x;
        var c = sharedB - Srp.SirpG.ModExp(x, Srp.SirpN) * gModN.ToBigInt();
        var u = c.ModExp(o, Srp.SirpN);
        var key = Crypto.Sha256(u.ToHex());
        return key;
    }

    internal static byte[] ModBytes(BigInteger dividend, BigInteger divisor)
    {
        var divisorSize = ToCompatibleByteArray(divisor).Length;

        var remainder = BigInteger.Remainder(dividend, divisor);
        var remainderBytes = ToCompatibleByteArray(remainder);
        var remainderSize = remainderBytes.Length;

        if (divisorSize == remainderSize)
            return remainderBytes;

        if (divisorSize < remainderSize)
            return remainderBytes[^2..]; // Take last two bytes

        // tSize > zSize => pad with zeros to divisorSize
        return new byte[divisorSize - remainderSize]
            .Concat(remainderBytes)
            .ToArray();
    }

    internal static byte[] ToCompatibleByteArray(BigInteger value)
    {
        var bytes = value.ToByteArray().Reverse().ToArray();
        return bytes.Length > 1 && bytes[0] == 0 ? bytes[1..] : bytes;
    }

    internal static string CalculateIdentity(string username, string keyUuid)
    {
        var s = new OutputSpanStream(stackalloc byte[64]);
        s.WriteBytes(Crypto.Sha256(keyUuid));
        s.WriteBytes(Crypto.Sha256(username.ToLowerInvariant().ToBytes()));
        return Crypto.Sha256(s.Span).ToUrlSafeBase64NoPadding();
    }

    internal static void VerifyKey(
        byte[] sessionKey,
        string username,
        string keyUuid,
        byte[] salt,
        BigInteger sharedA,
        BigInteger sharedB,
        RestClient rest
    )
    {
        var clientHash = CalculateClientHash(sessionKey, username, keyUuid, salt, sharedA, sharedB);

        var confirmKeyResponse = rest.PostJson<R.ServerHash>(
            "v2/auth/confirm-key",
            new Dictionary<string, object> { ["clientVerifyHash"] = clientHash.ToUrlSafeBase64NoPadding() }
        );

        if (!confirmKeyResponse.IsSuccessful)
            throw new InternalErrorException($"Request to {confirmKeyResponse.RequestUri} failed");

        // TODO: Verify the server hash here. For now, we trust the server.
    }

    internal static byte[] CalculateClientHash(
        byte[] sessionKey,
        string username,
        string keyUuid,
        byte[] salt,
        BigInteger sharedA,
        BigInteger sharedB
    )
    {
        // Calculate some hashes
        var sirpN = Crypto.Sha256(ToCompatibleByteArray(Srp.SirpN));
        var sirpG = Crypto.Sha256(ToCompatibleByteArray(Srp.SirpG));
        var identity = Crypto.Sha256(CalculateIdentity(username, keyUuid));

        var clientHash = Rental.With(
            2048,
            buffer =>
            {
                var s = new OutputSpanStream(buffer);

                // SHA256(SHA256(sirpN) ^ SHA256(sirpG))
                for (var i = 0; i < 32; i++)
                    s.WriteByte((byte)(sirpN[i] ^ sirpG[i]));

                s.WriteBytes(identity);
                s.WriteBytes(salt);
                s.WriteBytes(ToCompatibleByteArray(sharedA));
                s.WriteBytes(ToCompatibleByteArray(sharedB));
                s.WriteBytes(sessionKey);

                return Crypto.Sha256(s.Span[..s.Position]);
            }
        );
        return clientHash;
    }
}
