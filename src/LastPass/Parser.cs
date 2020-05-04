// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.LastPass
{
    internal static class Parser
    {
        public readonly struct Chunk
        {
            public readonly string Id;
            public readonly byte[] Payload;

            public Chunk(string id, byte[] payload)
            {
                Id = id;
                Payload = payload;
            }
        }

        // May return null when the chunk does not represent an account.
        // All secure notes are ACCTs but not all of them store account information.
        //
        // TODO: Add a test for the folder case!
        // TODO: Add a test case that covers secure note account!
        public static Account Parse_ACCT(Chunk chunk, byte[] encryptionKey, SharedFolder folder = null)
        {
            return chunk.Payload.Open(reader =>
            {
                var placeholder = "decryption failed";

                // Read all items
                var id = ReadItem(reader).ToUtf8();
                var name = Util.DecryptAes256Plain(ReadItem(reader), encryptionKey, placeholder);
                var group = Util.DecryptAes256Plain(ReadItem(reader), encryptionKey, placeholder);
                var url = ReadItem(reader).ToUtf8().DecodeHex().ToUtf8();

                // Ignore "group" accounts. They have no credentials.
                if (url == "http://group")
                    return null;

                var notes = Util.DecryptAes256Plain(ReadItem(reader), encryptionKey, placeholder);
                SkipItem(reader);
                SkipItem(reader);
                var username = Util.DecryptAes256Plain(ReadItem(reader), encryptionKey, placeholder);
                var password = Util.DecryptAes256Plain(ReadItem(reader), encryptionKey, placeholder);
                SkipItem(reader);
                SkipItem(reader);
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

                // Adjust the path to include the group and the shared folder, if any.
                var path = MakeAccountPath(group, folder);

                return new Account(id, name, username, password, url, path);
            });
        }

        // TODO: Write a test for the RSA case!
        public static SharedFolder Parse_SHAR(Chunk chunk, byte[] encryptionKey, RSAParameters rsaKey)
        {
            return chunk.Payload.Open(reader =>
            {
                // Id
                var id = ReadItem(reader).ToUtf8();

                // Key
                var rsaEncryptedFolderKey = ReadItem(reader);
                byte[] key;
                using (var rsa = new RSACryptoServiceProvider())
                {
                    rsa.ImportParameters(rsaKey);
                    key = rsa.Decrypt(rsaEncryptedFolderKey.ToUtf8().DecodeHex(), true).ToUtf8().DecodeHex();
                }

                // Name
                var encryptedName = ReadItem(reader);
                var name = Util.DecryptAes256Base64(encryptedName, key);

                return new SharedFolder(id, name, key);
            });
        }

        public static RSAParameters ParseEncryptedPrivateKey(string encryptedPrivateKey, byte[] encryptionKey)
        {
            var decrypted = Util.DecryptAes256(encryptedPrivateKey.DecodeHex(),
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
            var anotherEnclosingSequence = enclosingSequence.Value.Open(reader => {
                Asn1.SkipItem(reader);
                Asn1.SkipItem(reader);
                return Asn1.ExtractItem(reader);
            });
            var yetAnotherEnclosingSequence = Asn1.ParseItem(anotherEnclosingSequence.Value);

            return yetAnotherEnclosingSequence.Value.Open(reader => {
                Asn1.ExtractItem(reader);

                // There are occasional leading zeros that need to be stripped.
                byte[] ReadInteger() => Asn1.ExtractItem(reader).Value.SkipWhile(i => i == 0).ToArray();

                return new RSAParameters
                {
                    Modulus = ReadInteger(),
                    Exponent = ReadInteger(),
                    D = ReadInteger(),
                    P = ReadInteger(),
                    Q = ReadInteger(),
                    DP = ReadInteger(),
                    DQ = ReadInteger(),
                    InverseQ = ReadInteger()
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

        public static string MakeAccountPath(string group, SharedFolder folder)
        {
            if (folder == null)
                return string.IsNullOrEmpty(group) ? "(none)" : group;

            return string.IsNullOrEmpty(group) ? folder.Name : string.Format("{0}\\{1}", folder.Name, group);
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
                // TODO: Is this a good idea?
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
            return reader.ReadUInt32BigEndian();
        }

        public static byte[] ReadPayload(BinaryReader reader, uint size)
        {
            return reader.ReadBytes((int)size);
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
