// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
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

            throw new InvalidOperationException(string.Format("Unsupported PBES2 method: '{0}'",
                                                              method));
        }

        private static readonly char[] Base32Alphabet = "abcdefghijklmnopqrstuvwxyz234567".ToCharArray();
    }
}
