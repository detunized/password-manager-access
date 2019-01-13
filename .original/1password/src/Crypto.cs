// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Linq;
using System.Security.Cryptography;

namespace OnePassword
{
    internal static class Crypto
    {
        public static byte[] RandomBytes(int size)
        {
            using (var random = new RNGCryptoServiceProvider())
            {
                var bytes = new byte[size];
                random.GetBytes(bytes);
                return bytes;
            }
        }

        public static uint RandonUInt32()
        {
            return BitConverter.ToUInt32(RandomBytes(sizeof (uint)), 0);
        }

        public static string RandomUuid()
        {
            var random = new Random();
            var uuid = new char[26];

            for (int i = 0; i < uuid.Length; ++i)
                uuid[i] = Base32Alphabet[random.Next(Base32Alphabet.Length)];

            return new string(uuid);
        }

        public static byte[] Sha256(string message)
        {
            return Sha256(message.ToBytes());
        }

        public static byte[] Sha256(byte[] message)
        {
            using (var sha = new SHA256Managed())
                return sha.ComputeHash(message);
        }

        public static byte[] Hmac256(byte[] salt, string message)
        {
            return Hmac256(salt, message.ToBytes());
        }

        public static byte[] Hmac256(byte[] salt, byte[] message)
        {
            using (var hmac = new HMACSHA256 { Key = salt })
                return hmac.ComputeHash(message);
        }

        public static byte[] Hkdf(string method, byte[] ikm, byte[] salt)
        {
            return OnePassword.Hkdf.Generate(ikm: ikm,
                                             salt: salt,
                                             info: method.ToBytes(),
                                             byteCount: 32);
        }

        public static byte[] Pbes2(string method, string password, byte[] salt, int iterations)
        {
            switch (method)
            {
            case "PBES2-HS256":
            case "PBES2g-HS256":
                return Pbkdf2.GenerateSha256(password.ToBytes(), salt, iterations, 32);
            case "PBES2-HS512":
            case "PBES2g-HS512":
                return Pbkdf2.GenerateSha512(password.ToBytes(), salt, iterations, 32);
            }

            throw ExceptionFactory.MakeUnsupported(
                string.Format("PBES2: method '{0}' is not supported", method));
        }

        public static byte[] CalculateSessionHmacSalt(AesKey sessionKey)
        {
            return Hmac256(sessionKey.Key, SessionHmacSecret);
        }

        // TODO: Looks like we can get rid of clientInfo since the session has the UUID as well
        public static string CalculateClientHash(ClientInfo clientInfo, Session session)
        {
            return CalculateClientHash(clientInfo.AccountKey.Uuid, session.Id);
        }

        public static string CalculateClientHash(string accountKeyUuid, string sessionId)
        {
            var a = Sha256(accountKeyUuid);
            var b = Sha256(sessionId);
            return Sha256(a.Concat(b).ToArray()).ToBase64();
        }

        public static string HashRememberMeToken(string token, Session session)
        {
            return HashRememberMeToken(token, session.Id);
        }

        public static string HashRememberMeToken(string token, string sessionId)
        {
            return Hmac256(token.Decode64(), sessionId.Decode32()).ToBase64().Substring(0, 8);
        }

        private static readonly char[] Base32Alphabet = "abcdefghijklmnopqrstuvwxyz234567".ToCharArray();
        private const string SessionHmacSecret =
            "He never wears a Mac, in the pouring rain. Very strange.";
    }
}
