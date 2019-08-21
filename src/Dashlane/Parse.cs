// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Xml.Linq;
using System.Xml.XPath;

namespace PasswordManagerAccess.Dashlane
{
    public static class Parse
    {
        private static readonly byte[] Kwc3 = "KWC3".ToBytes();
        private static readonly byte[] Kwc5 = "KWC5".ToBytes();

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
            try
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
            catch (CryptographicException e)
            {
                throw new ParseException(
                    ParseException.FailureReason.IncorrectPassword,
                    "Decryption failed due to incorrect password or data corruption",
                    e);
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

            if (version.SequenceEqual(Kwc3))
                return new Blob(blob.Sub(saltLength + versionLength, int.MaxValue), salt, true, false, 1);

            // TODO: This is not correct. There's IV, not salt. I wish we could find an example of this in the wild.
            if (version.SequenceEqual(Kwc5))
                return new Blob(blob.Sub(68, int.MaxValue), blob.Sub(0, 16), false, true, 5);

            // New flexible format
            if (blob[0] == '$')
                return ParseFlexibleBlob(blob);

            // TODO: Replace with a ClientException
            throw new NotImplementedException("Unsupported encryption mode");
        }

        public static Blob ParseFlexibleBlob(byte[] blob)
        {
            // Pieces of the string joined with $ ($1$argon2d$16$3$32768$2$aes256$cbchmac$16$...)

            // This part is the key derivation configuration:
            //   - $1       - version, must be 1
            //   - $argon2d - method, must be "argon2d" or "pbkdf2"
            //
            // For argon2d:
            //   - $16     - salt length
            //   - $3      - time cost
            //   - $32768  - memory cost
            //   - $2      - parallelism
            //
            // For pbkdf2:
            //   - $16     - salt length
            //   - $10000  - number of iterations
            //   - $sha256 - hash method
            //
            // The next part is the cipher/encryption configuration:
            //   - $aes256  - cipher, must be aes256
            //   - $cbchmac - AES mode, must be cbchmac, cbc or gcm
            //   - $16      - IV length
            //
            // Signature is always "hmac"
            // IV derivation could be either "data" or "evpByteToKey"
            //
            // After the crypto configuration:
            //   - salt       - "salt length" bytes
            //   - IV         - "IV length" bytes
            //   - MAC        - 32 bytes
            //   - ciphertext - the rest

            var offset = 0;

            var version = GetNextComponent(blob, ref offset);
            if (version != "1")
                throw new InvalidOperationException();

            var method = GetNextComponent(blob, ref offset);
            switch (method)
            {
            case "argon2d":
                var argonSaltLength = int.Parse(GetNextComponent(blob, ref offset));
                var timeCost = int.Parse(GetNextComponent(blob, ref offset));
                var memoryCost = int.Parse(GetNextComponent(blob, ref offset));
                var parallelism = int.Parse(GetNextComponent(blob, ref offset));
                break;
            case "pbkdf2":
                var pbkdfSaltLength = int.Parse(GetNextComponent(blob, ref offset));
                var iterations = int.Parse(GetNextComponent(blob, ref offset));
                var hash = GetNextComponent(blob, ref offset);
                break;
            default:
                throw new InvalidOperationException();
            }

            var cipher = GetNextComponent(blob, ref offset);
            if (cipher != "aes256")
                throw new InvalidOperationException();

            var aesMode = GetNextComponent(blob, ref offset);
            if (!new[] {"cbc", "cbchmac", "gcm"}.Contains(aesMode))
                throw new InvalidOperationException();

            return new Blob();
        }

        public static string GetNextComponent(byte[] blob, ref int offset)
        {
            var end = GetNextDollar(blob, offset);
            var sub = blob.Sub(offset, end - offset);
            offset = end;
            return sub.ToUtf8();
        }

        public static int GetNextDollar(byte[] blob, int start)
        {
            for (var i = start; i < blob.Length; i++)
                if (blob[i] == '$')
                    return i;

            throw new InvalidOperationException();
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
                GetValueForKeyOrDefault(e, "Id"),
                GetValueForKeyOrDefault(e, "Title"),
                GetValueForKeyOrDefault(e, "Login"),
                GetValueForKeyOrDefault(e, "Password"),
                GetValueForKeyOrDefault(e, "Url"),
                GetValueForKeyOrDefault(e, "Note"));
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
    }
}
