// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Linq;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.OnePassword
{
    internal static class Util
    {
        public static string RandomUuid()
        {
            // TODO: Shouldn't this be using Crypto.RandomBytes?
            var random = new Random();
            var uuid = new char[26];

            for (int i = 0; i < uuid.Length; ++i)
                uuid[i] = Base32Alphabet[random.Next(Base32Alphabet.Length)];

            return new string(uuid);
        }

        public static byte[] Hkdf(string method, byte[] ikm, byte[] salt)
        {
            return Common.Hkdf.Generate(ikm: ikm,
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
                return Crypto.Pbkdf2Sha256(password: password,
                                           salt: salt,
                                           iterations: iterations,
                                           byteCount: 32);
            case "PBES2-HS512":
            case "PBES2g-HS512":
                return Crypto.Pbkdf2Sha512(password: password,
                                           salt: salt,
                                           iterations: iterations,
                                           byteCount: 32);
            }

            throw ExceptionFactory.MakeUnsupported(
                string.Format("PBES2: method '{0}' is not supported", method));
        }

        public static byte[] CalculateSessionHmacSalt(AesKey sessionKey)
        {
            return Crypto.HmacSha256(SessionHmacSecret, sessionKey.Key);
        }

        public static string CalculateClientHash(Session session)
        {
            return CalculateClientHash(session.KeyUuid, session.Id);
        }

        public static string CalculateClientHash(string accountKeyUuid, string sessionId)
        {
            var a = Crypto.Sha256(accountKeyUuid);
            var b = Crypto.Sha256(sessionId);
            return Crypto.Sha256(a.Concat(b).ToArray()).ToUrlSafeBase64NoPadding();
        }

        public static string HashRememberMeToken(string token, Session session)
        {
            return HashRememberMeToken(token, session.Id);
        }

        public static string HashRememberMeToken(string token, string sessionId)
        {
            return Crypto.HmacSha256(sessionId.Decode32(), token.Decode64Loose())
                .ToUrlSafeBase64NoPadding()
                .Substring(0, 8);
        }

        private static readonly char[] Base32Alphabet = "abcdefghijklmnopqrstuvwxyz234567".ToCharArray();
        private const string SessionHmacSecret = "He never wears a Mac, in the pouring rain. Very strange.";
    }
}
