// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Numerics;

namespace OnePassword
{
    // Performs a secure password exchange and generates a secret symmetric
    // session encryption key that couldn't be seen by a man in the middle.
    // See https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol
    // It's slightly modified so we have to roll our own.
    internal static class Srp
    {
        // Returns the session encryption key
        public static AesKey Perform(ClientInfo clientInfo, Session session, JsonHttpClient http)
        {
            var key = Perform(GenerateSecretA(), clientInfo, session, http);
            return new AesKey(session.Id, key);
        }

        //
        // Internal
        //

        internal static byte[] Perform(BigInteger secretA,
                                       ClientInfo clientInfo,
                                       Session session,
                                       JsonHttpClient http)
        {
            var sharedA = ComputeSharedA(secretA);
            var sharedB = ExchangeAForB(sharedA, session, http);
            ValidateB(sharedB);
            return ComputeKey(secretA, sharedA, sharedB, clientInfo, session);
        }

        internal static BigInteger GenerateSecretA()
        {
            return Crypto.RandomBytes(32).ToBigInt();
        }

        internal static BigInteger ComputeSharedA(BigInteger secretA)
        {
            return SirpG.ModExp(secretA, SirpN);
        }

        internal static BigInteger ExchangeAForB(BigInteger sharedA,
                                                 Session session,
                                                 JsonHttpClient http)
        {
            var response = http.Post("auth",
                                     new Dictionary<string, object>
                                     {
                                         {"sessionID", session.Id},
                                         {"userA", sharedA.ToHex()}
                                     });

            if (response.StringAt("sessionID") != session.Id)
                throw ExceptionFactory.MakeInvalidOperation("SRP: session ID doesn't match");

            return response.StringAt("userB").ToBigInt();
        }

        internal static void ValidateB(BigInteger sharedB)
        {
            if (sharedB % SirpN == 0)
                throw ExceptionFactory.MakeInvalidOperation("SRP: B validation failed");
        }

        internal static byte[] ComputeKey(BigInteger secretA,
                                          BigInteger sharedA,
                                          BigInteger sharedB,
                                          ClientInfo clientInfo,
                                          Session session)
        {
            // Some arbitrary crypto computation, variable names don't have much meaning
            var ab = sharedA.ToHex() + sharedB.ToHex();
            var hashAb = Crypto.Sha256(ab).ToBigInt();
            var s = session.Id.ToBytes().ToBigInt();
            var x = ComputeX(clientInfo, session);
            var y = sharedB - SirpG.ModExp(x, SirpN) * s;
            var z = y.ModExp(secretA + hashAb * x, SirpN);

            return Crypto.Sha256(z.ToHex());
        }

        internal static BigInteger ComputeX(ClientInfo clientInfo, Session session)
        {
            var method = session.SrpMethod;
            var iterations = session.Iterations;

            if (iterations == 0)
                throw ExceptionFactory.MakeUnsupported("SRP: 0 iterations is not supported");

            // TODO: Add constants for 1024, 6144 and 8192
            if (method != "SRPg-4096")
                throw ExceptionFactory.MakeUnsupported(
                    string.Format("SRP: method '{0}' is not supported", method));

            var k1 = Crypto.Hkdf(method: method,
                                 ikm: session.Salt,
                                 salt: clientInfo.Username.ToBytes());
            var k2 = Crypto.Pbes2(method: session.KeyMethod,
                                  password: clientInfo.Password,
                                  salt: k1,
                                  iterations: iterations);
            var x = clientInfo.AccountKey.CombineWith(k2);

            return x.ToBigInt();
        }

        //
        // Private
        //

        private static readonly BigInteger SirpN =
            ("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22" +
             "514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6" +
             "F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
             "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB" +
             "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E8603" +
             "9B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
             "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D" +
             "B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864" +
             "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" +
             "43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C" +
             "1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D" +
             "99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9" +
             "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF").ToBigInt();

        private static readonly BigInteger SirpG = new BigInteger(5);
    }
}
