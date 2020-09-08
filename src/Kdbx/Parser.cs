// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Kdbx
{
    internal static class Parser
    {
        public static void Parse(string filename, string password)
        {
            Parse(File.ReadAllBytes(filename), password);
        }

        //
        // Internal
        //

        internal static void Parse(byte[] blob, string password)
        {
            blob.Open(io =>
            {
                var magic1 = io.ReadUInt32();
                if (magic1 != Magic1)
                    throw MakeInvalidFormatError($"primary file signature is invalid: {magic1:x8}");

                var magic2 = io.ReadUInt32();
                if (!Magic2.Contains(magic2))
                    throw MakeInvalidFormatError($"secondary file signature is invalid: {magic2:x8}");

                var version = io.ReadUInt32();
                if (version != Version4)
                    throw MakeUnsupportedError($"Version {version:x8}");

                ReadHeader(io);

                var headerSize = io.BaseStream.Position;
                io.BaseStream.Seek(0, SeekOrigin.Begin);
                var headerBytes = io.ReadBytes((int)headerSize);
                var computedHeaderHash = Crypto.Sha256(headerBytes);
                var storedHeaderHash = io.ReadBytes(32);
                if (!computedHeaderHash.SequenceEqual(storedHeaderHash))
                    throw MakeInvalidFormatError("header hash doesn't match, the file is corrupted");
            });
        }

        internal static void ReadHeader(BinaryReader io)
        {
            for (;;)
            {
                var id = io.ReadByte();

                var size = io.ReadInt32();
                if (size < 0)
                    throw MakeInvalidFormatError($"header field {id} has negative size ({size})");

                switch (id)
                {
                // End (payload ignored)
                case 0:
                    io.ReadBytes(size);
                    return;

                // Comment (payload ignored)
                case 1:
                    io.ReadBytes(size);
                    break;

                // Cipher
                case 2:
                    if (size != 16)
                        throw MakeInvalidFormatError($"cipher field has incorrect size ({size})");

                    var cipherId = io.ReadBytes(size);
                    if (cipherId.SequenceEqual(AesCipherId))
                        Console.WriteLine("Cipher: AES");
                    else if (cipherId.SequenceEqual(ChaCha20CipherId))
                        Console.WriteLine("Cipher: ChaCha20");
                    else if (cipherId.SequenceEqual(TwoFishCipherId))
                        Console.WriteLine("Cipher: TwoFish");
                    else
                        throw MakeUnsupportedError($"Cipher '{cipherId.ToHex()}'");

                    break;

                // Compression method
                case 3:
                    if (size != 4)
                        throw MakeInvalidFormatError($"compression method field has incorrect size ({size})");

                    var compression = io.ReadInt32();
                    switch (compression)
                    {
                    case 0:
                        Console.WriteLine("Not compressed");
                        break;
                    case 1:
                        Console.WriteLine("GZip compressed");
                        break;
                    default:
                        throw MakeUnsupportedError($"Compression method {compression}");
                    }
                    break;

                // Master seed
                case 4:
                    var masterSeed = io.ReadBytes(size);
                    Console.WriteLine($"Master seed: {masterSeed.ToHex()}");
                    break;

                // Master IV
                case 7:
                    var masterIv = io.ReadBytes(size);
                    Console.WriteLine($"Master IV: {masterIv.ToHex()}");
                    break;

                // KDF parameters
                case 11:
                    Console.WriteLine($"KDF size: {size}");
                    var before = io.BaseStream.Position;
                    var kdf = ReadVariantDictionary(io);
                    var after = io.BaseStream.Position;
                    Console.WriteLine($"KDF parameters ({after - before})");
                    foreach (var i in kdf)
                    {
                        var value = i.Value.ToString();
                        if (i.Value is byte[] bytes)
                            value = bytes.ToHex();

                        Console.WriteLine($"  - {i.Key}: {value}");
                    }

                    break;

                default:
                    var payload = io.ReadBytes(size);
                    Console.WriteLine($"Header field id: {id}, size: {size}, payload: {payload.ToHex()}");
                    break;
                }
            }
        }

        private static Dictionary<string, object> ReadVariantDictionary(BinaryReader io)
        {
            var version = io.ReadInt16();
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
                Console.WriteLine($"key: {key} at {io.BaseStream.Position + valueSize:x}");

                // TODO: Verify sizes
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
                    66 => io.ReadBytes(valueSize),

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
        // Data
        //

        internal const uint Magic1 = 0x9aa2d903u;
        internal static readonly uint[] Magic2 = {0xb54bfb66u, 0xb54bfb67u};
        internal const uint Version4 = 0x00040000u;

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
