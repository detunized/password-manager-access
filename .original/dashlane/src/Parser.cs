// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Xml.Linq;
using System.Xml.XPath;

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

        public static byte[] Inflate(byte[] compressed)
        {
            using (var inputStream = new MemoryStream(compressed, false))
            using (var deflateStream = new DeflateStream(inputStream, CompressionMode.Decompress))
            using (var outputStream = new MemoryStream())
            {
                deflateStream.CopyTo(outputStream);
                return outputStream.ToArray();
            }
        }

        public struct Blob
        {
            public Blob(byte[] ciphertext, byte[] salt, bool compressed, bool useDerivedKey, int iterations)
                : this()
            {
                Ciphertext = ciphertext;
                Salt = salt;
                Compressed = compressed;
                UseDerivedKey = useDerivedKey;
                Iterations = iterations;
            }

            public readonly byte[] Ciphertext;
            public readonly byte[] Salt;
            public readonly bool Compressed;
            public readonly bool UseDerivedKey;
            public readonly int Iterations;
        }

        public static Blob ParseEncryptedBlob(byte[] blob)
        {
            const int saltLength = 32;
            const int versionLength = 4;

            var salt = blob.Sub(0, saltLength);
            if (salt.Length < saltLength)
                throw new ArgumentException("Blob is too short", "blob");

            var version = blob.Sub(saltLength, versionLength);
            return version.SequenceEqual(Kwc3)
                ? new Blob(blob.Sub(saltLength + versionLength, int.MaxValue), salt, true, false, 1)
                : new Blob(blob.Sub(saltLength, int.MaxValue), salt, false, true, 5);
        }

        public static byte[] DecryptBlob(byte[] blob, string password)
        {
            var parsed = ParseEncryptedBlob(blob);
            var key = ComputeEncryptionKey(password, parsed.Salt);
            var derivedKeyIv = DeriveEncryptionKeyAndIv(key, parsed.Salt, parsed.Iterations);
            var plaintext = DecryptAes256(
                parsed.Ciphertext,
                derivedKeyIv.Iv,
                parsed.UseDerivedKey ? derivedKeyIv.Key : key);

            return parsed.Compressed ? Inflate(plaintext.Sub(6, int.MaxValue)) : plaintext;
        }

        public static Account[] ExtractAccountsFromXml(string xml)
        {
            return XDocument.Parse(xml)
                .Descendants("KWAuthentifiant")
                .Select(ParseAccount)
                .ToArray();
        }

        public static Account ParseAccount(XElement e)
        {
            return new Account(
                id: GetValueForKeyOrDefault(e, "Id"),
                name: GetValueForKeyOrDefault(e, "Title"),
                username: GetValueForKeyOrDefault(e, "Login"),
                password: GetValueForKeyOrDefault(e, "Password"),
                url: GetValueForKeyOrDefault(e, "Url"),
                note: GetValueForKeyOrDefault(e, "Note"));
        }

        public static string GetValueForKeyOrDefault(XElement e, string key, string defaultValue = "")
        {
            var item = e.XPathSelectElement(string.Format("KWDataItem[@key='{0}']", key));
            return item != null ? item.Value : defaultValue;
        }

        public static Account[] ExtractEncryptedAccounts(byte[] blob, string password)
        {
            return ExtractAccountsFromXml(DecryptBlob(blob, password).ToUtf8());
        }

        public static readonly byte[] Kwc3 = "KWC3".ToBytes();
    }
}
