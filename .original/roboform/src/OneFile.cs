// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace RoboForm
{
    internal static class OneFile
    {
        public static JObject Parse(byte[] blob, string password)
        {
            if (blob.Length < 30) // magic(8) + flags(1) + checksum-type(1) + length(4) + md5(16)
                throw ParseError("File is too short");

            using (var io = new BinaryReader(new MemoryStream(blob)))
            {
                // 00-07 (8): magic ("onefile1")
                var magic = io.ReadBytes(8);
                if (!magic.SequenceEqual("onefile1".ToBytes()))
                    throw ParseError("Invalid signature: [{0}]", PrintBytes(magic));

                // 08 (1): flags
                //     - bit 0: set if the checksum is written into the file
                //     - bit 1: set if encrypted (fails if not set in the original JavaScript code)
                //     - bit 2: set if zipped
                var flags = io.ReadByte();
                var hasChecksum = (flags & 0x01) != 0;
                var isEncrypted = (flags & 0x02) != 0;
                var isCompressed = (flags & 0x04) != 0;

                // Doesn't fail in the original code, but they always check MD5 of the content
                if (!hasChecksum)
                    throw UnsupportedError("Unchecked content is not supported");

                // Fails in the original JavaScript code when not encrypted
                if (!isEncrypted)
                    throw UnsupportedError("Unencrypted content is not supported");

                // 09 (1): integrity check algorithm
                //     - 0: CRC32
                //     - 1: MD5 (hardcoded to use MD5, though there's code to handle other types)
                //     - 2: SHA-1
                //     - 3: SHA-256
                var checksumType = io.ReadByte();
                if (checksumType != 1)
                    throw ParseError("Invalid checksum type: {0}", checksumType);

                // 10-13 (4): encrypted content length (LE)
                var contentLength = (int)io.ReadUInt32LittleEndian();
                if (contentLength < 0)
                    throw ParseError("Content length is negative");

                // 14-29: (16) MD5 checksum
                var storedChecksum = io.ReadBytes(16);

                // 30-end: (contentLength): encrypted content
                var content = io.ReadBytes(contentLength);
                if (content.Length != contentLength)
                    throw ParseError("Content is too short");

                var actualChecksum = Crypto.Md5(content);
                if (!actualChecksum.SequenceEqual(storedChecksum))
                    throw ParseError("Checksum doesn't match");

                var compressed = Decrypt(content, password);
                var raw = isCompressed ? Decompress(compressed) : compressed;

                return ParseJson(raw);
            }
        }

        //
        // Internal
        //

        internal static byte[] Decrypt(byte[] content, string password)
        {
            if (content.Length < 15) // magic(8) + extra(1) + kdf(1) + iterations(4) + salt(1)
                throw ParseError("Content is too short");

            using (var io = new BinaryReader(new MemoryStream(content)))
            {
                // 00-07 (8): magic ("gsencst1")
                var magic = io.ReadBytes(8);
                if (!magic.SequenceEqual("gsencst1".ToBytes()))
                    throw ParseError("Invalid signature: [{0}]", PrintBytes(magic));

                // 08 (1): extra header length
                var extraLength = io.ReadByte();

                // 09 (1): key derivation function / encryption type
                //     - 0: PBKDF1_AES_SHA1 / AES-256-CBC
                //     - 1: PBKDF2_HMAC_SHA1 / AES-256-CBC
                //     - 2: PBKDF2_HMAC_SHA256 / AES-256-CBC
                //     - 3: PBKDF2_HMAC_SHA512 / AES-256-CBC
                //     - 4: PBKDF2_HMAC_SHA512 / AES-256-GCM
                var encryptionType = io.ReadByte();

                Func<byte[], byte[], int, int, byte[]> kdf;
                switch (encryptionType)
                {
                case 0:
                case 1:
                    throw UnsupportedError("SHA-1 based KDF is not supported");
                case 2:
                    kdf = Pbkdf2.GenerateSha256;
                    break;
                case 3:
                case 4:
                    kdf = Pbkdf2.GenerateSha512;
                    break;
                default:
                    throw ParseError("KDF/encryption type {0} is invalid", encryptionType);
                }

                // 10-13 (4): KDF iterations
                var iterations = io.ReadUInt32LittleEndian();
                if (iterations == 0 || iterations > 512 * 1024)
                    throw ParseError("KDF iteration count is invalid {0}", iterations);

                // 14 (1): salt length
                var saltLength = io.ReadByte();

                // 15-...: salt and extra header
                var salt = io.ReadBytes(saltLength);
                var extra = io.ReadBytes(extraLength);

                if (salt.Length != saltLength || extra.Length != extraLength)
                    throw ParseError("Content is too short");

                // Default is PKCS7 padding
                var padding = extra.Length > 0 && (extra[0] & 1) != 0
                    ? PaddingMode.None
                    : PaddingMode.PKCS7;

                // KDF produces both the key and IVs
                var keyIv = kdf(password.ToBytes(), salt, (int)iterations, 64);
                var key = keyIv.Take(32).ToArray();
                var iv = keyIv.Skip(32).Take(16).ToArray();

                // The rest is encrypted
                var ciphertext = io.ReadBytes((int)(content.Length - io.BaseStream.Position));

                // With AES-256-CBC there's no way to know if decrypted correctly.
                // It will later fail in decompression/JSON parsing.
                // TODO: Check for CryptographicException
                var plaintext = Crypto.DecryptAes256(ciphertext, key, iv, padding);

                // Skip garbage (something strange, but that's what they do)
                var xor = 0xAA;
                var garbageLength = 0;
                for (var i = 0; i < plaintext.Length && xor != 0; ++i)
                {
                    ++garbageLength;
                    xor ^= plaintext[i];
                }

                return plaintext.Skip(garbageLength).ToArray();
            }
        }

        internal static byte[] Decompress(byte[] content)
        {
            using (var gzipStream = new GZipStream(new MemoryStream(content, false),
                                                   CompressionMode.Decompress))
            using (var outputStream = new MemoryStream())
            {
                // TODO: Handle exceptions in case of corruption
                gzipStream.CopyTo(outputStream);
                return outputStream.ToArray();
            }
        }

        internal static JObject ParseJson(byte[] content)
        {
            try
            {
                return JObject.Parse(content.ToUtf8());
            }
            catch (JsonException e)
            {
                throw ParseError(e, "Corrupted content or decryption failed due to invalid password");
            }
        }

        //
        // Private
        //

        private static string PrintBytes(byte[] bytes)
        {
            return string.Join(", ", bytes.Select(i => i.ToString("x2")));
        }

        private static ClientException ParseError(string format, params object[] args)
        {
            return ParseError(null, format, args);
        }

        private static ClientException ParseError(Exception inner,
                                                  string format,
                                                  params object[] args)
        {
            return CreateException(inner, ClientException.FailureReason.ParseError, format, args);
        }

        private static ClientException UnsupportedError(string format, params object[] args)
        {
            return CreateException(null,
                                   ClientException.FailureReason.UnsupportedFeature,
                                   format,
                                   args);
        }

        private static ClientException CreateException(Exception inner,
                                                       ClientException.FailureReason reason,
                                                       string format,
                                                       params object[] args)
        {
            return new ClientException(reason, string.Format("Onefile: " + format, args), inner);
        }
    }
}
