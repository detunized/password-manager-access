// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace Dashlane
{
    static class Parser
    {
        public static byte[] ComputeEncryptionKey(string password, byte[] salt)
        {
            return new Rfc2898DeriveBytes(password, salt, 10204).GetBytes(32);
        }

        public static byte[] Sha1(byte[] bytes, int times)
        {
            var result = bytes;
            using (var sha = new SHA1Managed())
                for (var i = 0; i < times; ++i)
                    result = sha.ComputeHash(result);

            return result;
        }

        public struct KeyIvPair
        {
            public KeyIvPair(byte[] key, byte[] iv)
            {
                Key = key;
                Iv = iv;
            }

            public readonly byte[] Key;
            public readonly byte[] Iv;
        }

        public static KeyIvPair DeriveEncryptionKeyAndIv(byte[] key, byte[] salt, int iterations)
        {
            var saltyKey = key.Concat(salt.Take(8)).ToArray();
            var last = new byte[] {};
            IEnumerable<byte> joined = new byte[] {};

            for (var i = 0; i < 3; ++i)
            {
                last = Sha1(last.Concat(saltyKey).ToArray(), iterations);
                joined = joined.Concat(last);
            }

            return new KeyIvPair(
                key: joined.Take(32).ToArray(),
                iv: joined.Skip(32).Take(16).ToArray());
        }

        public static byte[] DecryptAes256(byte[] ciphertext, byte[] iv, byte[] encryptionKey)
        {
            using (var aes = new AesManaged { KeySize = 256, Key = encryptionKey, Mode = CipherMode.CBC, IV = iv })
            using (var decryptor = aes.CreateDecryptor())
            using (var inputStream = new MemoryStream(ciphertext, false))
            using (var cryptoStream = new CryptoStream(inputStream, decryptor, CryptoStreamMode.Read))
            using (var outputStream = new MemoryStream())
            {
                cryptoStream.CopyTo(outputStream);
                return outputStream.ToArray();
            }
        }
    }
}
