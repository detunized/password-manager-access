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
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Dashlane
{
    internal static class Parse
    {
        private static readonly byte[] Kwc3 = "KWC3".ToBytes();
        private static readonly byte[] Kwc5 = "KWC5".ToBytes();
        private static readonly byte[] NoBytes = new byte[0];

        private static readonly CryptoConfig Kwc3Config = new CryptoConfig(
            new Pbkdf2Config(Pbkdf2Config.HashMethodType.Sha1, 10204, 32),
            CryptoConfig.CipherModeType.Cbc,
            CryptoConfig.IvGenerationModeType.EvpByteToKey,
            CryptoConfig.SignatureModeType.None);

        private static readonly CryptoConfig Kwc5Config = new CryptoConfig(
            new NoKdfConfig(),
            CryptoConfig.CipherModeType.CbcHmac,
            CryptoConfig.IvGenerationModeType.Data,
            CryptoConfig.SignatureModeType.HmacSha256);

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

        public interface IKdfConfig
        {
            string Name { get; }
            int SaltLength { get; }
        }

        public class Argon2dConfig: IKdfConfig
        {
            public readonly int MemoryCost;
            public readonly int TimeCost;
            public readonly int Parallelism;

            public string Name => "argon2d";
            public int SaltLength { get; }

            public Argon2dConfig(int memoryCost, int timeCost, int parallelism, int saltLength)
            {
                MemoryCost = memoryCost;
                TimeCost = timeCost;
                Parallelism = parallelism;
                SaltLength = saltLength;
            }
        }

        public class Pbkdf2Config: IKdfConfig
        {
            public enum HashMethodType
            {
                Sha1,
                Sha256,
            }

            public readonly HashMethodType HashMethod;
            public readonly int Iterations;

            public string Name => "pbkdf2";
            public int SaltLength { get; }

            public Pbkdf2Config(HashMethodType hashMethod, int iterations, int saltLength)
            {
                HashMethod = hashMethod;
                Iterations = iterations;
                SaltLength = saltLength;
            }
        }

        public class NoKdfConfig: IKdfConfig
        {
            public string Name => "none";
            public int SaltLength => 0;
        }

        public class CryptoConfig
        {
            public enum CipherModeType
            {
                Cbc,
                CbcHmac,
                Gcm,
            }

            public enum SignatureModeType
            {
                None,
                HmacSha256,
            }

            public enum IvGenerationModeType
            {
                Data,
                EvpByteToKey,
            }

            public readonly IKdfConfig KdfConfig;
            public readonly CipherModeType CipherMode;
            public readonly IvGenerationModeType IvGenerationMode;
            public readonly SignatureModeType SignatureMode;

            public CryptoConfig(IKdfConfig kdfConfig,
                                CipherModeType cipherMode,
                                IvGenerationModeType ivGenerationMode,
                                SignatureModeType signatureMode)
            {
                KdfConfig = kdfConfig;
                CipherMode = cipherMode;
                IvGenerationMode = ivGenerationMode;
                SignatureMode = signatureMode;
            }
        }

        public class Blob
        {
            public Blob(byte[] ciphertext,
                        byte[] salt,
                        byte[] iv,
                        byte[] hash,
                        bool compressed,
                        bool useDerivedKey,
                        int iterations,
                        CryptoConfig cryptoConfig)
            {
                Ciphertext = ciphertext;
                Salt = salt;
                Iv = iv;
                Hash = hash;
                Compressed = compressed;
                // TODO: Should be replaced with CryptoConfig
                UseDerivedKey = useDerivedKey;
                // TODO: Should be replaced with CryptoConfig
                Iterations = iterations;
                CryptoConfig = cryptoConfig;
            }

            public readonly byte[] Ciphertext;
            public readonly byte[] Salt;
            public readonly byte[] Iv;
            public readonly byte[] Hash;
            public readonly CryptoConfig CryptoConfig;

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
                return new Blob(ciphertext: blob.Sub(saltLength + versionLength, int.MaxValue),
                                salt: salt,
                                iv: NoBytes,
                                hash: NoBytes,
                                compressed: true,
                                useDerivedKey: false,
                                iterations: 1,
                                cryptoConfig: Kwc3Config);

            if (version.SequenceEqual(Kwc5))
                throw new UnsupportedFeatureException("KWC5 encryption scheme is not supported");

            // TODO: Add KWC5 support. It's impossible to test, since there are no real examples of this in the wild
            // This is how to parse it:
            // return new Blob(ciphertext: blob.Sub(68, int.MaxValue),
            //                 salt: NoBytes,
            //                 iv: blob.Sub(0, 16),
            //                 hash: blob.Sub(36, 32),
            //                 compressed: false,
            //                 useDerivedKey: true,
            //                 iterations: 5,
            //                 cryptoConfig: Kwc5Config);

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

            var offset = 1;

            var version = GetNextComponent(blob, ref offset);
            if (version != "1")
                throw new InvalidOperationException();

            IKdfConfig kdfConfig = null;
            switch (GetNextComponent(blob, ref offset))
            {
            case "argon2d":
                {
                    var saltLength = int.Parse(GetNextComponent(blob, ref offset));
                    var timeCost = int.Parse(GetNextComponent(blob, ref offset));
                    var memoryCost = int.Parse(GetNextComponent(blob, ref offset));
                    var parallelism = int.Parse(GetNextComponent(blob, ref offset));
                    kdfConfig = new Argon2dConfig(memoryCost: memoryCost,
                                                  timeCost: timeCost,
                                                  parallelism: parallelism,
                                                  saltLength: saltLength);
                }
                break;
            case "pbkdf2":
                {
                    var saltLength = int.Parse(GetNextComponent(blob, ref offset));
                    var iterations = int.Parse(GetNextComponent(blob, ref offset));

                    Pbkdf2Config.HashMethodType hashMethod;
                    string hashMethodStr = GetNextComponent(blob, ref offset);
                    switch (hashMethodStr)
                    {
                    case "sha1":
                        hashMethod = Pbkdf2Config.HashMethodType.Sha1;
                        break;
                    case "sha256":
                        hashMethod = Pbkdf2Config.HashMethodType.Sha256;
                        break;
                    default:
                        throw new InvalidOperationException($"Unknown PBKDF2 hashing method: {hashMethodStr}");
                    }

                    kdfConfig = new Pbkdf2Config(hashMethod: hashMethod,
                                                 iterations: iterations,
                                                 saltLength: saltLength);
                }
                break;
            default:
                throw new InvalidOperationException();
            }

            var cipher = GetNextComponent(blob, ref offset);
            if (cipher != "aes256")
                throw new InvalidOperationException();

            CryptoConfig.CipherModeType cipherMode;
            var cipherModeStr = GetNextComponent(blob, ref offset);
            switch (cipherModeStr)
            {
            case "cbc":
                cipherMode = CryptoConfig.CipherModeType.Cbc;
                break;
            case "cbchmac":
                cipherMode = CryptoConfig.CipherModeType.CbcHmac;
                break;
            case "gcm":
                cipherMode = CryptoConfig.CipherModeType.Gcm;
                break;
            default:
                throw new InvalidOperationException($"Unknown cipher mode: {cipherModeStr}");
            }

            var cryptoConfig = new CryptoConfig(kdfConfig,
                                                cipherMode,
                                                CryptoConfig.IvGenerationModeType.Data,
                                                CryptoConfig.SignatureModeType.HmacSha256);

            var ivLength = int.Parse(GetNextComponent(blob, ref offset));

            var salt = blob.Sub(offset, kdfConfig.SaltLength);
            offset += kdfConfig.SaltLength;

            var iv = blob.Sub(offset, ivLength);
            offset += ivLength;

            var hash = blob.Sub(offset, 32);
            offset += 32;

            var ciphertext = blob.Sub(offset, int.MaxValue);

            return new Blob(ciphertext: ciphertext,
                            salt: salt,
                            iv: iv,
                            hash: hash,
                            compressed: false,
                            useDerivedKey: false,
                            iterations: 0,
                            cryptoConfig: cryptoConfig);
        }

        public static string GetNextComponent(byte[] blob, ref int offset)
        {
            var end = GetNextDollar(blob, offset);
            var sub = blob.Sub(offset, end - offset);
            offset = end + 1;
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
