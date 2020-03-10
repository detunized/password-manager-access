// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Xml.Linq;
using System.Xml.XPath;
using Konscious.Security.Cryptography;
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

        public interface IKdfConfig
        {
            string Name { get; }
            int SaltLength { get; }

            byte[] Derive(byte[] password, byte[] salt);
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

            public byte[] Derive(byte[] password, byte[] salt)
            {
                // TODO: Move this to Crypto?
                var argon2d = new Argon2d(password)
                {
                    Salt = salt,
                    MemorySize = MemoryCost,
                    Iterations = TimeCost,
                    DegreeOfParallelism = Parallelism,
                };

                return argon2d.GetBytes(32);
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

            public byte[] Derive(byte[] password, byte[] salt)
            {
                switch (HashMethod)
                {
                case HashMethodType.Sha1:
                    return Pbkdf2.GenerateSha1(password, salt, Iterations, 32);
                case HashMethodType.Sha256:
                    return Pbkdf2.GenerateSha256(password, salt, Iterations, 32);
                }

                throw new InternalErrorException($"Unknown hash method {HashMethod}");
            }
        }

        public class NoKdfConfig: IKdfConfig
        {
            public string Name => "none";
            public int SaltLength => 0;

            public byte[] Derive(byte[] password, byte[] salt)
            {
                return NoBytes;
            }
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
            public readonly byte[] Ciphertext;
            public readonly byte[] Salt;
            public readonly byte[] Iv;
            public readonly byte[] Hash;
            public readonly CryptoConfig CryptoConfig;

            public Blob(byte[] ciphertext, byte[] salt, byte[] iv, byte[] hash, CryptoConfig cryptoConfig)
            {
                Ciphertext = ciphertext;
                Salt = salt;
                Iv = iv;
                Hash = hash;
                CryptoConfig = cryptoConfig;
            }
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
                                cryptoConfig: Kwc3Config);

            if (version.SequenceEqual(Kwc5))
                throw new UnsupportedFeatureException("KWC5 encryption scheme is not supported");

            // TODO: Add KWC5 support. It's impossible to test, since there are no real examples of this in the wild
            // This is how to parse it:
            // return new Blob(ciphertext: blob.Sub(68, int.MaxValue),
            //                 salt: NoBytes,
            //                 iv: blob.Sub(0, 16),
            //                 hash: blob.Sub(36, 32),
            //                 cryptoConfig: Kwc5Config);

            // New flexible format
            if (blob[0] == '$')
                return ParseFlexibleBlob(blob);

            throw new InternalErrorException("Invalid blob format");
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

            return new Blob(ciphertext: ciphertext, salt: salt, iv: iv, hash: hash, cryptoConfig: cryptoConfig);
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
            return DecryptBlob(blob, PasswordToBytes(password));
        }

        public static byte[] DecryptBlob(byte[] blob, byte[] password)
        {
            // 1. Parse
            var parsed = ParseEncryptedBlob(blob);

            // 2. Derive the key and IV
            //
            // Depending on the mode, the key is either the actual encryption key or an interim key
            // that is used to derive the iv, HMAC and the encryption keys.
            var key = ComputeEncryptionKey(password, parsed.Salt, parsed.CryptoConfig);
            var iv = DeriveIv(key, parsed);

            // 3. Derive the encryption key and the HMAC key
            var keyHmacKey = DeriveKeyAndHmacKey(key, parsed.CryptoConfig);
            var encryptionKey = keyHmacKey.Item1;
            var hmacKey = keyHmacKey.Item2;

            // 4. Check the MAC
            if (!DoesHashMatch(parsed, iv, hmacKey))
                throw new BadCredentialsException(
                    "The password is incorrect or the data in the vault is corrupted (MAC doesn't match)");

            // 5. Decrypt
            var plaintext = Decrypt(parsed.Ciphertext, iv, encryptionKey);

            // 6. Inflate
            return Inflate(plaintext.Sub(6, int.MaxValue));
        }

        // TODO: This function does nothing special. Inline this?
        public static byte[] ComputeEncryptionKey(byte[] password, byte[] salt, CryptoConfig config)
        {
            // TODO: This is slow for some of the algorithms, this needs to be cached or large
            // vaults would take forever to open.
            return config.KdfConfig.Derive(password, salt);
        }

        public static byte[] PasswordToBytes(string password)
        {
            // TODO: Dashlane does some sort of tricky conversion of non ASCII passwords. Figure this out!
            //       For now we just throw as non supported.
            if (password.Any(x => x > 127))
                throw new UnsupportedFeatureException("Non ASCII passwords are not supported");

            return password.ToBytes();
        }

        public static byte[] DeriveIv(byte[] key, Blob blob)
        {
            switch (blob.CryptoConfig.IvGenerationMode)
            {
            case CryptoConfig.IvGenerationModeType.Data:
                return blob.Iv;
            case CryptoConfig.IvGenerationModeType.EvpByteToKey:
                // The key part of this is only used in KWC5 which is not support ATM
                return DeriveEncryptionKeyAndIv(key, blob.Salt).Iv;
            }

            throw new InternalErrorException($"Unexpected IV generation mode {blob.CryptoConfig.IvGenerationMode}");
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

        public static KeyIvPair DeriveEncryptionKeyAndIv(byte[] key, byte[] salt)
        {
            var saltyKey = key.Concat(salt.Take(8)).ToArray();
            var last = new byte[] { };
            IEnumerable<byte> joined = new byte[] { };

            for (var i = 0; i < 3; ++i)
            {
                last = Crypto.Sha1(last.Concat(saltyKey).ToArray());
                joined = joined.Concat(last);
            }

            return new KeyIvPair(
                key: joined.Take(32).ToArray(),
                iv: joined.Skip(32).Take(16).ToArray());
        }

        public static Tuple<byte[], byte[]> DeriveKeyAndHmacKey(byte[] key, CryptoConfig config)
        {
            switch (config.SignatureMode)
            {
            case CryptoConfig.SignatureModeType.None:
                return new Tuple<byte[], byte[]>(key, NoBytes);
            case CryptoConfig.SignatureModeType.HmacSha256:
                var keys = Crypto.Sha512(key);
                return new Tuple<byte[], byte[]>(keys.Sub(0, 32), keys.Sub(32, 32));
            }

            throw new InternalErrorException($"Unexpected signature mode {config.SignatureMode}");
        }

        public static bool DoesHashMatch(Blob blob, byte[] iv, byte[] hmacKey)
        {
            switch (blob.CryptoConfig.SignatureMode)
            {
            case CryptoConfig.SignatureModeType.None:
                return true;
            case CryptoConfig.SignatureModeType.HmacSha256:
                var hash = Crypto.HmacSha256(iv.Concat(blob.Ciphertext).ToArray(), hmacKey);
                return hash.SequenceEqual(blob.Hash);
            }

            throw new InternalErrorException($"Unexpected signature mode {blob.CryptoConfig.SignatureMode}");
        }

        public static byte[] Decrypt(byte[] ciphertext, byte[] iv, byte[] encryptionKey)
        {
            try
            {
                return Crypto.DecryptAes256Cbc(ciphertext, iv, encryptionKey);
            }
            catch (CryptoException e)
            {
                throw new BadCredentialsException("The password is incorrect", e);
            }
        }

        public static byte[] Inflate(byte[] compressed)
        {
            using var inputStream = new MemoryStream(compressed, false);
            using var deflateStream = new DeflateStream(inputStream, CompressionMode.Decompress);
            return deflateStream.ReadAll();
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
            var item = e.XPathSelectElement($"KWDataItem[@key='{key}']");
            return item != null ? item.Value : defaultValue;
        }

        public static Account[] ExtractEncryptedAccounts(byte[] blob, string password)
        {
            return ExtractAccountsFromXml(DecryptBlob(blob, password).ToUtf8());
        }
    }
}
