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
using System.Xml.Linq;
using System.Xml.XPath;
using CSChaCha20;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Kdbx
{
    internal static class Parser
    {
        public static Account[] Parse(string filename, string password)
        {
            using var io = File.OpenRead(filename);
            return Parse(io, password);
        }

        //
        // Internal
        //

        internal static Account[] Parse(Stream input, string password)
        {
            var info = ParseHeader(input, password);
            input.Seek(info.HeaderSize, SeekOrigin.Begin);
            var body = ParseBody(input, info);
            return ParseAccounts(body);
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
                return ParseHeader(headerBytes.AsRoSpan(0, read), password);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(headerBytes);
            }
        }

        internal static DatabaseInfo ParseHeader(ReadOnlySpan<byte> blob, string password)
        {
            return ParseHeader(blob.ToStream(), password);
        }

        internal static DatabaseInfo ParseHeader(SpanStream io, string password)
        {
            var header = io.Read<Header>();

            if (header.Signature1 != Magic1)
                throw MakeInvalidFormatError($"primary file signature is invalid: {header.Signature1:x8}");

            if (!Magic2.Contains(header.Signature2))
                throw MakeInvalidFormatError($"secondary file signature is invalid: {header.Signature2:x8}");

            if (header.MajorVersion != Version4)
                throw MakeUnsupportedError($"Version {header.MajorVersion}.{header.MinorVersion}");

            var info = ReadEncryptionInfo(ref io);

            var headerSize = io.Position;
            io.Rewind();
            var headerBytes = io.ReadBytes(headerSize);

            var computedHash = Crypto.Sha256(headerBytes);
            var storedHash = io.ReadBytes(32);

            if (!Crypto.AreEqual(storedHash, computedHash))
                throw MakeInvalidFormatError("Header hash doesn't match");

            var storedHeaderMac = io.ReadBytes(32);
            var compositeKey = Util.ComposeMasterKey(password);

            var derivedKey = DeriveMasterKey(compositeKey, info.Kdf);
            var (encryptionKey, hmacKey) = Util.DeriveDatabaseKeys(derivedKey, info.Seed);

            var blockHmacKey = Util.ComputeBlockHmacKey(hmacKey, ulong.MaxValue);
            var computedHeaderMac = Crypto.HmacSha256(blockHmacKey, headerBytes);

            if (!Crypto.AreEqual(storedHeaderMac, computedHeaderMac))
                throw MakeInvalidFormatError("Header MAC doesn't match");

            return new DatabaseInfo(headerSize: io.Position,
                                    isCompressed: info.IsCompressed,
                                    cipher: info.Cipher,
                                    encryptionKey: encryptionKey,
                                    iv: info.Iv,
                                    hmacKey: hmacKey);
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
                    else if (payload.SequenceEqual(TwofishCipherId))
                        cipher = Cipher.Twofish;
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

        internal static byte[] DeriveMasterKey(byte[] compositeKey, Dictionary<string, object> kdf)
        {
            if (!(kdf.GetOrDefault("$UUID", null) is byte[] id))
                throw MakeInvalidFormatError("Failed to identify the KDF method");

            if (id.SequenceEqual(Aes3KdfId) || id.SequenceEqual(Aes4KdfId))
                return Util.DeriveMasterKeyAes(compositeKey, kdf);

            if (id.SequenceEqual(Argon2KdfId))
                return Util.DeriveMasterKeyArgon2(compositeKey, kdf);

            throw MakeUnsupportedError($"KDF method {id.ToHex()}");
        }

        internal static Body ParseBody(Stream input, in DatabaseInfo info)
        {
            using var bs = new BlockStream(input, info.HmacKey);

            using IDisposable engine = info.Cipher switch
            {
                Cipher.Aes => CreateAes(info),
                Cipher.ChaCha20 => CreateChaCha20(info),
                Cipher.Twofish => CreateTwofish(info),
                _ => throw MakeUnsupportedError($"Cipher {info.Cipher}"),
            };

            using ICryptoTransform decryptor = info.Cipher switch
            {
                Cipher.Aes => ((Aes)engine).CreateDecryptor(),
                Cipher.ChaCha20 => ChaCha20CryptoTransform.CreateDecryptor((ChaCha20)engine),
                Cipher.Twofish => ((Twofish)engine).CreateDecryptor(),
                _ => throw MakeUnsupportedError($"Cipher {info.Cipher}"),
            };

            using var cryptoStream = new CryptoStream(bs, decryptor, CryptoStreamMode.Read);

            using var bodyStream = info.IsCompressed
                ? (Stream)new GZipStream(cryptoStream, CompressionMode.Decompress, leaveOpen: true)
                : cryptoStream;

            var randomStream = ParseInnerHeader(bodyStream);
            var xml = XDocument.Load(bodyStream);

            return new Body(randomStream, xml);
        }

        internal static Aes CreateAes(in DatabaseInfo info)
        {
            var aes = Aes.Create();
            aes.KeySize = 256;
            aes.Key = info.EncryptionKey;
            aes.Mode = CipherMode.CBC;
            aes.IV = info.Iv;
            aes.Padding = PaddingMode.PKCS7;

            return aes;
        }

        internal static ChaCha20 CreateChaCha20(in DatabaseInfo info)
        {
            return new ChaCha20(info.EncryptionKey, info.Iv, 0);
        }

        internal static Twofish CreateTwofish(in DatabaseInfo info)
        {
            return new Twofish
            {
                Key = info.EncryptionKey,
                IV = info.Iv
            };
        }

        internal static RandomStream ParseInnerHeader(Stream input)
        {
            var buffer = ArrayPool<byte>.Shared.Rent(4096);
            try
            {
                return ParseInnerHeader(input, buffer);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        internal static RandomStream ParseInnerHeader(Stream input, byte[] buffer)
        {
            BaseException MakeError(string info) => MakeInvalidFormatError($"inner header is corrupted: {info}");

            int? randomStreamId = null;
            byte[] randomStreamKey = null;

            for (;;)
            {
                // Each item starts with a byte ID and a 32 bit size
                if (!input.TryReadExact(buffer, 0, 5))
                    throw MakeError("failed to read item header");

                var itemHeader = new SpanStream(buffer, 0, 5);
                var id = itemHeader.ReadByte();
                var size = itemHeader.ReadInt32();

                switch (id)
                {
                // ID 0 marks the end of the inner header
                case 0:
                    if (size != 0)
                        throw MakeError("ID 0 must contain no payload");

                    if (randomStreamId == null)
                        throw MakeError("random stream ID not found");

                    if (randomStreamKey == null)
                        throw MakeError("random stream key not found");

                    return new RandomStream(randomStreamId.Value, randomStreamKey);

                // Random stream ID
                case 1:
                    if (size != 4)
                        throw MakeError($"random stream ID must 4 bytes long, got {size}");

                    if (!input.TryReadExact(buffer, 0, size))
                        throw MakeError("failed to read random stream ID");

                    randomStreamId = new SpanStream(buffer, 0, size).ReadInt32();
                    break;

                // Random stream key
                case 2:
                    if (size != 64)
                        throw MakeError($"random stream key must 64 bytes long, got {size}");

                    if (!input.TryReadExact(buffer, 0, size))
                        throw MakeError("failed to read random stream key");

                    randomStreamKey = buffer.Sub(0, size);
                    break;

                // Binary attachment, just skip them
                case 3:
                    // Size has only 31 valid bits
                    if (size < 0)
                        throw MakeError($"size of binary attachment is invalid ({size})");

                    // Skip the payload
                    if (!input.TrySkip(size, buffer))
                        throw MakeError($"failed to skip item with ID {id}");

                    break;

                default:
                    throw MakeError($"invalid item ID {id}");
                }
            }
        }

        internal static Account[] ParseAccounts(in Body body)
        {
            DecryptProtectedValues(body);

            var accounts = new List<Account>();
            var root = body.Xml.XPathSelectElement("//Root/Group");
            ParseAccounts(root, "", accounts);

            return accounts.ToArray();
        }

        internal static void DecryptProtectedValues(in Body body)
        {
            var xml = body.Xml.ToString();

            var id = body.RandomStream.Id;
            if (id != 3)
                throw MakeUnsupportedError($"Random stream ID {id}");

            var keyIv = Crypto.Sha512(body.RandomStream.Key);
            var cipher = new ChaCha20Engine(keyIv.Sub(0, 32), keyIv.Sub(32, 12));

            var values = body.Xml.XPathSelectElements("//Value[@Protected='True']").ToArray();
            foreach (var v in values)
            {
                // TODO: Remove temporaries. Can we do in-place decryption?
                var raw = v.Value.Decode64();
                var dec = new byte[raw.Length];
                cipher.ProcessBytes(raw, 0, raw.Length, dec, 0);
                v.Value = dec.ToUtf8();
            }
        }

        internal static void ParseAccounts(XElement folder, string path, List<Account> accounts)
        {
            foreach (var i in folder.Elements())
            {
                switch (i.Name.LocalName)
                {
                case "Group":
                    var name = i.Element("Name")?.Value ?? "-";
                    ParseAccounts(i, path.IsNullOrEmpty() ? name : $"{path}/{name}", accounts);
                    break;
                case "Entry":
                    accounts.Add(ParseAccount(i, path));
                    break;
                }
            }
        }

        internal static Account ParseAccount(XElement xml, string path)
        {
            var id = xml.Element("UUID")?.Value.Decode64().ToHex() ?? "";
            var name = "";
            var username = "";
            var password = "";
            var url = "";
            var note = "";

            foreach (var s in xml.Elements("String"))
            {
                var value = s.Element("Value")?.Value ?? "";
                switch (s.Element("Key")?.Value)
                {
                case "Title":
                    name = value;
                    break;
                case "UserName":
                    username = value;
                    break;
                case "Password":
                    password = value;
                    break;
                case "URL":
                    url = value;
                    break;
                case "Notes":
                    note = value;
                    break;
                }
            }

            return new Account(id: id,
                               name: name,
                               username: username,
                               password: password,
                               url: url,
                               note: note,
                               path: path);
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
            public readonly Cipher Cipher;
            public readonly byte[] EncryptionKey;
            public readonly byte[] Iv;
            public readonly byte[] HmacKey;

            public DatabaseInfo(int headerSize,
                                bool isCompressed,
                                Cipher cipher,
                                byte[] encryptionKey,
                                byte[] iv,
                                byte[] hmacKey)
            {
                HeaderSize = headerSize;
                IsCompressed = isCompressed;
                EncryptionKey = encryptionKey;
                Iv = iv;
                HmacKey = hmacKey;
                Cipher = cipher;
            }
        }

        internal enum Cipher
        {
            Aes,
            ChaCha20,
            Twofish,
        }

        internal readonly struct EncryptionInfo
        {
            public readonly bool IsCompressed;
            public readonly Cipher Cipher;
            public readonly byte[] Seed;
            public readonly byte[] Iv;
            public readonly Dictionary<string, object> Kdf;

            public EncryptionInfo(bool isCompressed,
                                  Cipher cipher,
                                  byte[] seed,
                                  byte[] iv,
                                  Dictionary<string, object> kdf)
            {
                IsCompressed = isCompressed;
                Cipher = cipher;
                Seed = seed;
                Iv = iv;
                Kdf = kdf;
            }
        }

        internal readonly struct RandomStream
        {
            public readonly int Id;
            public readonly byte[] Key;

            public RandomStream(int id, byte[] key)
            {
                Id = id;
                Key = key;
            }
        }

        internal readonly struct Body
        {
            public readonly RandomStream RandomStream;
            public readonly XDocument Xml;

            public Body(RandomStream randomStream, XDocument xml)
            {
                RandomStream = randomStream;
                Xml = xml;
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
            0x31, 0xC1, 0xF2, 0xE6, 0xBF, 0x71, 0x43, 0x50,
            0xBE, 0x58, 0x05, 0x21, 0x6A, 0xFC, 0x5A, 0xFF,
        };

        internal static readonly byte[] ChaCha20CipherId =
        {
            0xD6, 0x03, 0x8A, 0x2B, 0x8B, 0x6F, 0x4C, 0xB5,
            0xA5, 0x24, 0x33, 0x9A, 0x31, 0xDB, 0xB5, 0x9A,
        };

        internal static readonly byte[] TwofishCipherId =
        {
            0xAD, 0x68, 0xF2, 0x9F, 0x57, 0x6F, 0x4B, 0xB9,
            0xA3, 0x6A, 0xD4, 0x7A, 0xF9, 0x65, 0x34, 0x6C,
        };

        internal static readonly byte[] Aes3KdfId =
        {
            0xC9, 0xD9, 0xF3, 0x9A, 0x62, 0x8A, 0x44, 0x60,
            0xBF, 0x74, 0x0D, 0x08, 0xC1, 0x8A, 0x4F, 0xEA,
        };

        internal static readonly byte[] Aes4KdfId =
        {
            0x7C, 0x02, 0xBB, 0x82, 0x79, 0xA7, 0x4A, 0xC0,
            0x92, 0x7D, 0x11, 0x4A, 0x00, 0x64, 0x82, 0x38,
        };

        internal static readonly byte[] Argon2KdfId =
        {
            0xEF, 0x63, 0x6D, 0xDF, 0x8C, 0x29, 0x44, 0x4B,
            0x91, 0xF7, 0xA9, 0xA4, 0x03, 0xE3, 0x0A, 0x0C,
        };
    }
}
