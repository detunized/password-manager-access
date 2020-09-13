// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Kdbx
{
    internal static class Parser
    {
        public static void Parse(string filename, string password)
        {
            using var io = File.OpenRead(filename);
            Parse(io, password);
        }

        //
        // Internal
        //

        internal static void Parse(Stream input, string password)
        {
            var info = ParseHeader(input, password);
            input.Seek(info.HeaderSize, SeekOrigin.Begin);
            ParseBody(input, info);
        }

        internal static DatabaseInfo ParseHeader(Stream input, string password)
        {
            // There's no way to say how long the header is until it's parsed fully.
            // We just assume that the header should fit in 64k.
            const int size = 65536;
            var headerBytes = ArrayPool<byte>.Shared.Rent(size);
            try
            {
                var read = input.Read(headerBytes, 0, size);
                return ParseHeader(headerBytes.AsRoSpan().Slice(0, read), password);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(headerBytes);
            }
        }

        internal static DatabaseInfo ParseHeader(ReadOnlySpan<byte> blob, string password)
        {
            var io = blob.ToStream();
            var header = io.Read<Header>();

            if (header.Signature1 != Magic1)
                throw MakeInvalidFormatError($"primary file signature is invalid: {header.Signature1:x8}");

            if (!Magic2.Contains(header.Signature2))
                throw MakeInvalidFormatError($"secondary file signature is invalid: {header.Signature2:x8}");

            if (header.MajorVersion != Version4)
                throw MakeUnsupportedError($"Version {header.MajorVersion}.{header.MinorVersion}");

            var info = ReadEncryptionInfo(ref io);
            var headerEnd = io.Position;

            var computedHash = Crypto.Sha256(blob.Slice(0, headerEnd));
            var storedHash = io.ReadBytes(32);

            if (!Crypto.AreEqual(storedHash, computedHash))
                throw MakeInvalidFormatError("Header hash doesn't match");

            var storedHeaderMac = io.ReadBytes(32);
            var passwordHash = Crypto.Sha256(password);
            var compositeRawKey = Crypto.Sha256(passwordHash);

            using var aes = Aes.Create();
            aes.KeySize = 256;
            aes.Key = (byte[])info.Kdf["S"];
            aes.Mode = CipherMode.ECB;
            aes.IV = new byte[16];
            aes.Padding = PaddingMode.PKCS7;

            using var encryptor = aes.CreateEncryptor();
            var derivedKey = compositeRawKey.Sub(0, 32);

            // Derive
            for (ulong i = 0; i < (ulong)info.Kdf["R"]; i++)
            {
                encryptor.TransformBlock(derivedKey, 0, 16, derivedKey, 0);
                encryptor.TransformBlock(derivedKey, 16, 16, derivedKey, 16);
            }

            derivedKey = Crypto.Sha256(derivedKey);
            var k2 = info.Seed.Concat(derivedKey).ToArray();
            var encryptionKey = Crypto.Sha256(k2);
            var hmacKey = Crypto.Sha512(k2.Append((byte)1).ToArray());

            var blockHmacKey = Util.ComputeBlockHmacKey(hmacKey, ulong.MaxValue);
            var computedHeaderMac = Crypto.HmacSha256(blockHmacKey, blob.Slice(0, headerEnd).ToArray()); // TODO: Remove .ToArray

            if (!Crypto.AreEqual(storedHeaderMac, computedHeaderMac))
                throw MakeInvalidFormatError("Header MAC doesn't match");

            return new DatabaseInfo(headerSize: io.Position,
                                    isCompressed: info.Compressed,
                                    encryptionKey: encryptionKey,
                                    iv: info.Iv,
                                    hmacKey: hmacKey);
        }

        internal static void ParseBody(Stream input, in DatabaseInfo info)
        {
            using var bs = new BlockStream(input, info.HmacKey);

            using var aes = Aes.Create();
            aes.KeySize = 256;
            aes.Key = info.EncryptionKey;
            aes.Mode = CipherMode.CBC;
            aes.IV = info.Iv;
            aes.Padding = PaddingMode.PKCS7;

            using var decryptor = aes.CreateDecryptor();
            using var cryptoStream = new CryptoStream(bs, decryptor, CryptoStreamMode.Read);

            var plaintext = new GZipStream(cryptoStream, CompressionMode.Decompress).ReadAll();
            // TODO: Skip the binary header. Then comes the XML
        }

        internal static EncryptionInfo ReadEncryptionInfo(ref SpanStream io)
        {
            bool? compressed = null;
            Cipher? cipher = null;
            byte[] seed = null;
            byte[] iv = null;
            Dictionary<string, object> kdf = null;

            static void CheckField(object f, string name)
            {
                if (f == null)
                    throw MakeInvalidFormatError($"{name} not found in the header");
            }

            for (;;)
            {
                var header = io.Read<FieldHeader>();
                var payload = io.ReadBytes(header.Size);

                switch (header.Id)
                {
                // Done (payload ignored)
                case 0:
                    CheckField(compressed, "compressed flag");
                    CheckField(cipher, "cipher");
                    CheckField(seed, "master seed");
                    CheckField(iv, "master IV");
                    CheckField(kdf, "KDF parameters");

                    return new EncryptionInfo(compressed.Value, cipher.Value, seed, iv, kdf);

                // Cipher
                case 2:
                    if (payload.Length != 16)
                        throw MakeInvalidFormatError($"cipher field has incorrect size ({payload.Length})");

                    if (payload.SequenceEqual(AesCipherId))
                        cipher = Cipher.Aes;
                    else if (payload.SequenceEqual(ChaCha20CipherId))
                        cipher = Cipher.ChaCha20;
                    else if (payload.SequenceEqual(TwoFishCipherId))
                        cipher = Cipher.TwoFish;
                    else
                        throw MakeUnsupportedError($"Cipher '{payload.ToHex()}'");

                    break;

                // Compression method
                case 3:
                    if (payload.Length != 4)
                        throw MakeInvalidFormatError($"compression method field has incorrect size ({payload.Length})");

                    var compression = new SpanStream(payload).ReadUInt32();
                    switch (compression)
                    {
                    // None
                    case 0:
                        compressed = false;
                        break;

                    // GZip
                    case 1:
                        compressed = true;
                        break;

                    // Unknown
                    default:
                        throw MakeUnsupportedError($"Compression method {compression}");
                    }
                    break;

                // Master seed
                case 4:
                    seed = payload.ToArray();
                    break;

                // Master IV
                case 7:
                    iv = payload.ToArray();
                    break;

                // KDF parameters
                case 11:
                    kdf = ReadVariantDictionary(payload);
                    break;

                // Other fields are ignored
                }
            }
        }

        private static Dictionary<string, object> ReadVariantDictionary(ReadOnlySpan<byte> span)
        {
            return ReadVariantDictionary(span.ToStream());
        }

        private static Dictionary<string, object> ReadVariantDictionary(SpanStream io)
        {
            var version = io.ReadUInt16();
            if (version != 0x0100)
                throw MakeUnsupportedError($"Variant dictionary version {version}");

            var result = new Dictionary<string, object>();

            for (;;)
            {
                var type = io.ReadByte();
                if (type == 0)
                    return result;

                var keySize = io.ReadInt32();
                var key = io.ReadBytes(keySize).ToUtf8();
                var valueSize = io.ReadInt32();

                result[key] = type switch
                {
                    // UInt32
                    4 => io.ReadUInt32(),

                    // UInt64
                    5 => io.ReadUInt64(),

                    // Bool
                    8 => io.ReadByte() != 0,

                    // Int32
                    12 => io.ReadInt32(),

                    // Int64
                    13 => io.ReadInt64(),

                    // UTF-8 string
                    24 => io.ReadBytes(valueSize).ToUtf8(),

                    // byte[]
                    66 => io.ReadBytes(valueSize).ToArray(),

                    _ => throw MakeInvalidFormatError($"item type {type} is invalid"),
                };
            }
        }

        internal static BaseException MakeInvalidFormatError(string message)
        {
            return new InternalErrorException($"Invalid format: {message}");
        }

        internal static BaseException MakeUnsupportedError(string message)
        {
            return new UnsupportedFeatureException($"{message} is not supported");
        }

        //
        // Local data types
        //

        internal readonly struct DatabaseInfo
        {
            public readonly int HeaderSize;
            public readonly bool IsCompressed;
            public readonly byte[] EncryptionKey;
            public readonly byte[] Iv;
            public readonly byte[] HmacKey;

            public DatabaseInfo(int headerSize, bool isCompressed, byte[] encryptionKey, byte[] iv, byte[] hmacKey)
            {
                HeaderSize = headerSize;
                IsCompressed = isCompressed;
                EncryptionKey = encryptionKey;
                Iv = iv;
                HmacKey = hmacKey;
            }
        }

        internal enum Cipher
        {
            Aes,
            ChaCha20,
            TwoFish,
        }

        internal readonly struct EncryptionInfo
        {
            public readonly bool Compressed;
            public readonly Cipher Cipher;
            public readonly byte[] Seed;
            public readonly byte[] Iv;
            public readonly Dictionary<string, object> Kdf;

            public EncryptionInfo(bool compressed,
                                  Cipher cipher,
                                  byte[] seed,
                                  byte[] iv,
                                  Dictionary<string, object> kdf)
            {
                Compressed = compressed;
                Cipher = cipher;
                Seed = seed;
                Iv = iv;
                Kdf = kdf;
            }
        }

        //
        // Models
        //

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal readonly struct Header
        {
            public readonly uint Signature1;
            public readonly uint Signature2;
            public readonly ushort MinorVersion;
            public readonly ushort MajorVersion;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal readonly struct FieldHeader
        {
            public readonly byte Id;
            public readonly int Size;
        }

        //
        // Data
        //

        internal const uint Magic1 = 0x9aa2d903u;
        internal static readonly uint[] Magic2 = {0xb54bfb66u, 0xb54bfb67u};
        internal const ushort Version4 = 4;

        internal static readonly byte[] AesCipherId =
        {
            0x31, 0xc1, 0xf2, 0xe6, 0xbf, 0x71, 0x43, 0x50,
            0xbe, 0x58, 0x05, 0x21, 0x6a, 0xfc, 0x5a, 0xff,
        };

        internal static readonly byte[] ChaCha20CipherId =
        {
            0xD6, 0x03, 0x8a, 0x2b, 0x8b, 0x6f, 0x4c, 0xB5,
            0xa5, 0x24, 0x33, 0x9a, 0x31, 0xdb, 0xb5, 0x9a,
        };

        internal static readonly byte[] TwoFishCipherId =
        {
            0xad, 0x68, 0xf2, 0x9f, 0x57, 0x6f, 0x4b, 0xb9,
            0xa3, 0x6a, 0xd4, 0x7a, 0xf9, 0x65, 0x34, 0x6c,
        };
    }
}
