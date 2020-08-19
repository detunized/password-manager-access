// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Linq;
using Newtonsoft.Json;
using PasswordManagerAccess.Common;
using R = PasswordManagerAccess.OnePassword.Response;

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

            throw new UnsupportedFeatureException($"Method '{method}' is not supported");
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

        internal static T Decrypt<T>(Encrypted encrypted, IDecryptor decryptor)
        {
            var plaintext = decryptor.Decrypt(encrypted).ToUtf8();
            try
            {
                return JsonConvert.DeserializeObject<T>(plaintext);
            }
            catch (JsonException e)
            {
                throw new InternalErrorException("Failed to parse JSON", e);
            }
        }

        internal static T Decrypt<T>(R.Encrypted encrypted, IDecryptor decryptor)
        {
            return Decrypt<T>(Encrypted.Parse(encrypted), decryptor);
        }

        internal static void DecryptAesKey(Encrypted encryptedAesKey, Keychain keychain)
        {
            keychain.Add(AesKey.Parse(Decrypt<R.AesKey>(encryptedAesKey, keychain)));
        }

        internal static void DecryptAesKey(R.Encrypted encryptedAesKey, Keychain keychain)
        {
            DecryptAesKey(Encrypted.Parse(encryptedAesKey), keychain);
        }

        internal static void DecryptRsaKey(Encrypted encryptedRsaKey, Keychain keychain)
        {
            keychain.Add(RsaKey.Parse(Decrypt<R.RsaKey>(encryptedRsaKey, keychain)));
        }

        internal static void DecryptRsaKey(R.Encrypted encryptedRsaKey, Keychain keychain)
        {
            DecryptRsaKey(Encrypted.Parse(encryptedRsaKey), keychain);
        }

        private static readonly char[] Base32Alphabet = "abcdefghijklmnopqrstuvwxyz234567".ToCharArray();
        private const string SessionHmacSecret = "He never wears a Mac, in the pouring rain. Very strange.";
    }
}
