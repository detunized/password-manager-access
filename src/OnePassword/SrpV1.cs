// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Numerics;
using PasswordManagerAccess.Common;
using R = PasswordManagerAccess.OnePassword.Response;

namespace PasswordManagerAccess.OnePassword
{
    // Performs a secure password exchange and generates a secret symmetric
    // session encryption key that couldn't be seen by a man in the middle.
    // See https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol
    // It's slightly modified so we have to roll our own.
    internal static class SrpV1
    {
        // Returns the session encryption key
        public static AesKey Perform(Credentials credentials, SrpInfo srpInfo, string sessionId, RestClient rest)
        {
            var key = Perform(Srp.GenerateSecretA(), credentials, srpInfo, sessionId, rest);
            return new AesKey(sessionId, key);
        }

        //
        // Internal
        //

        internal static byte[] Perform(BigInteger secretA, Credentials credentials, SrpInfo srpInfo, string sessionId, RestClient rest)
        {
            var sharedA = Srp.ComputeSharedA(secretA);
            var sharedB = ExchangeAForB(sharedA, sessionId, rest);
            Srp.ValidateB(sharedB);
            return ComputeKey(secretA, sharedA, sharedB, credentials, srpInfo, sessionId);
        }

        internal static BigInteger ExchangeAForB(BigInteger sharedA, string sessionId, RestClient rest)
        {
            var response = rest.PostJson<R.AForBV1>(
                "v1/auth",
                new Dictionary<string, object> { ["sessionID"] = sessionId, ["userA"] = sharedA.ToHex() }
            );

            // TODO: Do we need better error handling here?
            if (!response.IsSuccessful)
                throw new InternalErrorException($"Request to {response.RequestUri} failed");

            if (response.Data.SessionId != sessionId)
                throw new InternalErrorException("Session ID doesn't match");

            return response.Data.B.ToBigInt();
        }

        internal static byte[] ComputeKey(
            BigInteger secretA,
            BigInteger sharedA,
            BigInteger sharedB,
            Credentials credentials,
            SrpInfo srpInfo,
            string sessionId
        )
        {
            // Some arbitrary crypto computation, variable names don't have a lot of meaning
            var ab = sharedA.ToHex() + sharedB.ToHex();
            var hashAb = Crypto.Sha256(ab).ToBigInt();
            var s = sessionId.ToBytes().ToBigInt();
            var x = credentials.SrpX.IsNullOrEmpty() ? ComputeX(credentials, srpInfo) : credentials.SrpX.DecodeHex().ToBigInt();
            var y = sharedB - Srp.SirpG.ModExp(x, Srp.SirpN) * s;
            var z = y.ModExp(secretA + hashAb * x, Srp.SirpN);

            return Crypto.Sha256(z.ToHex());
        }

        internal static BigInteger ComputeX(Credentials credentials, SrpInfo srpInfo)
        {
            var method = srpInfo.SrpMethod;
            var iterations = srpInfo.Iterations;

            if (iterations == 0)
                throw new UnsupportedFeatureException("0 iterations is not supported");

            // TODO: Add constants for 1024, 6144 and 8192
            if (method != "SRPg-4096")
                throw new UnsupportedFeatureException($"Method '{method}' is not supported");

            var k1 = Util.Hkdf(method: method, ikm: srpInfo.Salt, salt: credentials.Username.ToLowerInvariant().ToBytes());
            var k2 = Util.Pbes2(method: srpInfo.KeyMethod, password: credentials.Password, salt: k1, iterations: iterations);
            var x = credentials.ParsedAccountKey.CombineWith(k2);

            return x.ToBigInt();
        }
    }
}
