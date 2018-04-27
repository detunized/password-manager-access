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

        // May return null when the chunk does not represent an account.
        // All secure notes are ACCTs but not all of them store account information.
        //
        // TODO: Add a test for the folder case!
        // TODO: Add a test case that covers secure note account!
        public static Account Parse_ACCT(Chunk chunk, byte[] encryptionKey, SharedFolder folder = null)
        {
            Debug.Assert(chunk.Id == "ACCT");

            return WithBytes(chunk.Payload, reader =>
            {
                var placeholder = "decryption failed";

                // Read all items
                var id = ReadItem(reader).ToUtf8();
                var name = DecryptAes256Plain(ReadItem(reader), encryptionKey, placeholder);
                var group = DecryptAes256Plain(ReadItem(reader), encryptionKey, placeholder);
                var url = ReadItem(reader).ToUtf8().DecodeHex().ToUtf8();
                var notes = DecryptAes256Plain(ReadItem(reader), encryptionKey, placeholder);
                2.Times(() => SkipItem(reader));
                var username = DecryptAes256Plain(ReadItem(reader), encryptionKey, placeholder);
                var password = DecryptAes256Plain(ReadItem(reader), encryptionKey, placeholder);
                2.Times(() => SkipItem(reader));
                var secureNoteMarker = ReadItem(reader).ToUtf8();

                // Parse secure note
                if (secureNoteMarker == "1")
                {
                    var type = "";
                    ParseSecureNoteServer(notes, ref type, ref url, ref username, ref password);

                    // Only the some secure notes contain account-like information
                    if (!AllowedSecureNoteTypes.Contains(type))
                        return null;
                }

                // Override the group name with the shared folder name if any.
                if (folder != null)
                    group = folder.Name;

                return new Account(id, name, username, password, url, group);
            });
        }

        // TODO: Write a test for the RSA case!
        public static SharedFolder Parse_SHAR(Chunk chunk, byte[] encryptionKey, RSAParameters rsaKey)
        {
            Debug.Assert(chunk.Id == "SHAR");

            return WithBytes(chunk.Payload, reader =>
            {
                var id = ReadItem(reader).ToUtf8();
                var rsaEncryptedFolderKey = ReadItem(reader);
                var encryptedName = ReadItem(reader);
                2.Times(() => SkipItem(reader));
                var aesEncryptedFolderKey = ReadItem(reader);

                byte[] key = null;

                // Shared folder encryption key might come already in pre-decrypted form,
                // where it's only AES encrypted with the regular encryption key.
                if (aesEncryptedFolderKey.Length > 0)
                {
                    key = DecryptAes256Plain(aesEncryptedFolderKey, encryptionKey).DecodeHex();
                }
                else
                {
                    // When the key is blank, then there's an RSA encrypted key, which has to
                    // be decrypted first before use.
                    using (var rsa = new RSACryptoServiceProvider())
                    {
                        rsa.ImportParameters(rsaKey);
                        key = rsa.Decrypt(rsaEncryptedFolderKey.ToUtf8().DecodeHex(), true).ToUtf8().DecodeHex();
                    }
                }

                return new SharedFolder(id, DecryptAes256Base64(encryptedName, key), key);
            });
        }

        public static RSAParameters ParseEcryptedPrivateKey(string encryptedPrivateKey, byte[] encryptionKey)
        {
            var decrypted = DecryptAes256(encryptedPrivateKey.DecodeHex(),
                                          encryptionKey,
                                          CipherMode.CBC,
                                          encryptionKey.Take(16).ToArray());

            const string header = "LastPassPrivateKey<";
            const string footer = ">LastPassPrivateKey";
            if (!decrypted.StartsWith(header) || !decrypted.EndsWith(footer))
                throw new ParseException(ParseException.FailureReason.CorruptedBlob, "Failed to decrypt private key");

            var asn1EncodedKey = decrypted.Substring(header.Length,
                                                     decrypted.Length - header.Length - footer.Length).DecodeHex();

            var enclosingSequence = Asn1.ParseItem(asn1EncodedKey);
            var anotherEnclosingSequence = WithBytes(enclosingSequence.Value, reader => {
                2.Times(() => Asn1.ExtractItem(reader));
                return Asn1.ExtractItem(reader);
            });
            var yetAnotherEnclosingSequence = Asn1.ParseItem(anotherEnclosingSequence.Value);

            return WithBytes(yetAnotherEnclosingSequence.Value, reader => {
                Asn1.ExtractItem(reader);

                // There are occasional leading zeros that need to be stripped.
                Func<byte[]> readInteger =
                    () => Asn1.ExtractItem(reader).Value.SkipWhile(i => i == 0).ToArray();

                return new RSAParameters
                {
                    Modulus = readInteger(),
                    Exponent = readInteger(),
                    D = readInteger(),
                    P = readInteger(),
                    Q = readInteger(),
                    DP = readInteger(),
                    DQ = readInteger(),
                    InverseQ = readInteger()
                };
            });
        }

        public static void ParseSecureNoteServer(string notes,
                                                 ref string type,
                                                 ref string url,
                                                 ref string username,
                                                 ref string password)
        {
            foreach (var i in notes.Split('\n'))
            {
                var keyValue = i.Split(new[] {':'}, 2);
                if (keyValue.Length < 2)
                    continue;

                switch (keyValue[0])
                {
                case "NoteType":
                    type = keyValue[1];
                    break;
                case "Hostname":
                    url = keyValue[1];
                    break;
                case "Username":
                    username = keyValue[1];
                    break;
                case "Password":
                    password = keyValue[1];
                    break;
                }
            }
        }

        public static List<Chunk> ExtractChunks(BinaryReader reader)
        {
            var chunks = new List<Chunk>();
            try
            {
                while (reader.BaseStream.Position < reader.BaseStream.Length)
                    chunks.Add(ReadChunk(reader));
            }
            catch (EndOfStreamException)
            {
                // In case the stream is truncated we just ignore the incomplete chunk.
            }

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

        public static string DecryptAes256Plain(byte[] data, byte[] encryptionKey, string defaultValue)
        {
            return DecryptAes256WithDefaultValue(data, encryptionKey, defaultValue, DecryptAes256Plain);
        }

        public static string DecryptAes256Base64(byte[] data, byte[] encryptionKey, string defaultValue)
        {
            return DecryptAes256WithDefaultValue(data, encryptionKey, defaultValue, DecryptAes256Base64);
        }

        public static string DecryptAes256Plain(byte[] data, byte[] encryptionKey)
        {
            var length = data.Length;

            if (length == 0)
                return "";
            else if (data[0] == '!' && length % 16 == 1 && length > 32)
                return DecryptAes256CbcPlain(data, encryptionKey);
            else
                return DecryptAes256EcbPlain(data, encryptionKey);
        }

        public static string DecryptAes256Base64(byte[] data, byte[] encryptionKey)
        {
            var length = data.Length;

            if (length == 0)
                return "";
            else if (data[0] == '!')
                return DecryptAes256CbcBase64(data, encryptionKey);
            else
                return DecryptAes256EcbBase64(data, encryptionKey);
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

            using (var aes = new AesManaged {KeySize = 256, Key = encryptionKey, Mode = mode, IV = iv})
            using (var decryptor = aes.CreateDecryptor())
            using (var stream = new MemoryStream(data, false))
            using (var cryptoStream = new CryptoStream(stream, decryptor, CryptoStreamMode.Read))
            using (var reader = new StreamReader(cryptoStream))
            {
                // TODO: StreamReader is a text reader. This might fail with arbitrary binary encrypted
                //       data. Luckily we have only text encrypted. Pay attention when refactoring!
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

        private static string DecryptAes256WithDefaultValue(byte[] data,
                                                            byte[] encryptionKey,
                                                            string defaultValue,
                                                            Func<byte[], byte[], string> decrypt)
        {
            try
            {
                return decrypt(data, encryptionKey);
            }
            catch (CryptographicException)
            {
                return defaultValue;
            }
        }

        private static readonly HashSet<string> AllowedSecureNoteTypes = new HashSet<string>
        {
            "Server",
            "Email Account",
            "Database",
            "Instant Messenger",
        };
    }
}
