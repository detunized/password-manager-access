// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Numerics;

namespace OnePassword
{
    // TODO: See if we need all that state here. It's easier to test a bunch
    //       of static functions than a class with state.

    // Performs a secure password exchange and generates a secret symmetric
    // session encryption key that couldn't be seen by a man in the middle.
    // See https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol
    // It's slightly modified so we have to roll our own.
    internal class Srp
    {
        // Returns the session encryption key
        public static byte[] Perform(JsonHttpClient http, Session session)
        {
            return new Srp(http).Perform(session);
        }

        internal Srp(JsonHttpClient http)
        {
            _http = http;
        }

        internal byte[] Perform(Session session)
        {
            return Perform(session, GenerateSecretA());
        }

        internal byte[] Perform(Session session, BigInteger secretA)
        {
            var sharedA = ComputeSharedA(secretA);
            var sharedB = ExchangeAForB(sharedA, session);
            ValidateB(sharedB);
            return ComputeKey();
        }

        internal BigInteger GenerateSecretA()
        {
            return new BigInteger(Crypto.RandomBytes(32));
        }

        internal BigInteger ComputeSharedA(BigInteger secretA)
        {
            return BigInteger.ModPow(SirpG, secretA, SirpN);
        }

        internal BigInteger ExchangeAForB(BigInteger sharedA, Session session)
        {
            var response = _http.Post("userB",
                                      new Dictionary<string, object>()
                                      {
                                          {"sessionID", session.Id},
                                          {"userA", sharedA.ToString("x")}
                                      });

            if (response.StringAt("sessionID") != session.Id)
                throw new InvalidOperationException("Invalid response: session ID doesn't match");

            return response.StringAt("userB").ToBigInt();
        }

        internal void ValidateB(BigInteger sharedB)
        {
            if (sharedB % SirpN == 0)
                throw new InvalidOperationException("B validation failed");
        }

        internal byte[] ComputeKey()
        {
            // TODO: Implement this
            return new byte[0];
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

        private readonly JsonHttpClient _http;
    }
}
