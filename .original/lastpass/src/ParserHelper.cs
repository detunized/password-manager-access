// Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace LastPass
{
    static class ParserHelper
    {
        public class Chunk
        {
            public Chunk(string id, byte[] payload)
            {
                Id = id;
                Payload = payload;
            }

            public string Id { get; private set; }
            public byte[] Payload { get; private set; }
        }

        public static Account Parse_ACCT(Chunk chunk, byte[] encryptionKey)
        {
            Debug.Assert(chunk.Id == "ACCT");

            return WithBytes(chunk.Payload, reader =>
            {
                var id = ReadItem(reader).ToUtf8();
                var name = DecryptAes256(ReadItem(reader), encryptionKey);
                var group = DecryptAes256(ReadItem(reader), encryptionKey);
                var url = ReadItem(reader).ToUtf8().DecodeHex().ToUtf8();
                SkipItem(reader);
                SkipItem(reader);
                SkipItem(reader);
                var username = DecryptAes256(ReadItem(reader), encryptionKey);
                var password = DecryptAes256(ReadItem(reader), encryptionKey);

                return new Account(id, name, username, password, url, group);
            });
        }

        // TODO: Return a proper object!
        // TODO: Write a test for this!
        public static byte[] Parse_SHAR(Chunk chunk, byte[] encryptionKey)
        {
            Debug.Assert(chunk.Id == "SHAR");

            return WithBytes(chunk.Payload, reader =>
            {
                // TODO: Parse the other fields!
                for (int i = 0; i < 5; ++i)
                    SkipItem(reader);

                return DecryptAes256(ReadItem(reader), encryptionKey).DecodeHex();
            });
        }

        public static List<Chunk> ExtractChunks(BinaryReader reader)
        {
            var chunks = new List<Chunk>();
            while (reader.BaseStream.Position < reader.BaseStream.Length)
                chunks.Add(ReadChunk(reader));

            return chunks;
        }

        public static Chunk ReadChunk(BinaryReader reader)
        {
            // LastPass blob chunk is made up of 4-byte ID, big endian 4-byte size and payload of that size
            // Example:
            //   0000: 'IDID'
            //   0004: 4
            //   0008: 0xDE 0xAD 0xBE 0xEF
            //   000C: --- Next chunk ---

            return new Chunk(ReadId(reader),
                             ReadPayload(reader, ReadSize(reader)));
        }

        public static byte[] ReadItem(BinaryReader reader)
        {
            // An item in an itemized chunk is made up of the big endian size and the payload of that size
            // Example:
            //   0000: 4
            //   0004: 0xDE 0xAD 0xBE 0xEF
            //   0008: --- Next item ---

            return ReadPayload(reader, ReadSize(reader));
        }

        public static void SkipItem(BinaryReader reader)
        {
            // See ReadItem for item description.
            reader.BaseStream.Seek(ReadSize(reader), SeekOrigin.Current);
        }

        public static string ReadId(BinaryReader reader)
        {
            return reader.ReadBytes(4).ToUtf8();
        }

        public static uint ReadSize(BinaryReader reader)
        {
            return reader.ReadUInt32().FromBigEndian();
        }

        public static byte[] ReadPayload(BinaryReader reader, uint size)
        {
            return reader.ReadBytes((int)size);
        }

        public static string DecryptAes256(byte[] data, byte[] encryptionKey)
        {
            var length = data.Length;
            var length16 = length % 16;
            var length64 = length % 64;

            if (length == 0)
                return "";
            else if (length16 == 0)
                return DecryptAes256EcbPlain(data, encryptionKey);
            else if (length64 == 0 || length64 == 24 || length64 == 44)
                return DecryptAes256EcbBase64(data, encryptionKey);
            else if (length16 == 1)
                return DecryptAes256CbcPlain(data, encryptionKey);
            else if (length64 == 6 || length64 == 26 || length64 == 50)
                return DecryptAes256CbcBase64(data, encryptionKey);

            throw new ArgumentException("Input doesn't seem to be AES-256 encrypted");
        }

        public static string DecryptAes256EcbPlain(byte[] data, byte[] encryptionKey)
        {
            return DecryptAes256(data, encryptionKey, CipherMode.ECB);
        }

        public static string DecryptAes256EcbBase64(byte[] data, byte[] encryptionKey)
        {
            return DecryptAes256(data.ToUtf8().Decode64(), encryptionKey, CipherMode.ECB);
        }

        public static string DecryptAes256CbcPlain(byte[] data, byte[] encryptionKey)
        {
            return DecryptAes256(data.Skip(17).ToArray(),
                                 encryptionKey,
                                 CipherMode.CBC,
                                 data.Skip(1).Take(16).ToArray());
        }

        public static string DecryptAes256CbcBase64(byte[] data, byte[] encryptionKey)
        {
            return DecryptAes256(data.Skip(26).ToArray().ToUtf8().Decode64(),
                                 encryptionKey,
                                 CipherMode.CBC,
                                 data.Skip(1).Take(24).ToArray().ToUtf8().Decode64());
        }

        public static string DecryptAes256(byte[] data, byte[] encryptionKey, CipherMode mode)
        {
            return DecryptAes256(data, encryptionKey, mode, new byte[16]);
        }

        public static string DecryptAes256(byte[] data, byte[] encryptionKey, CipherMode mode, byte[] iv)
        {
            if (data.Length == 0)
                return "";

            using (var aes = new AesManaged { KeySize = 256, Key = encryptionKey, Mode = mode, IV = iv })
            using (var decryptor = aes.CreateDecryptor())
            using (var stream = new MemoryStream(data, false))
            using (var cryptoStream = new CryptoStream(stream, decryptor, CryptoStreamMode.Read))
            using (var reader = new StreamReader(cryptoStream))
            {
                return reader.ReadToEnd();
            }
        }

        public static void WithBytes(byte[] bytes, Action<BinaryReader> action)
        {
            WithBytes(bytes, (reader) => {
                action(reader);
                return 0;
            });
        }

        public static TResult WithBytes<TResult>(byte[] bytes, Func<BinaryReader, TResult> action)
        {
            using (var stream = new MemoryStream(bytes, false))
            using (var reader = new BinaryReader(stream))
                return action(reader);
        }
    }
}
