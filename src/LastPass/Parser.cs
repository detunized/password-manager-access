// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

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
        public static Account Parse_ACCT(Chunk chunk, byte[] encryptionKey, SharedFolder folder, ParserOptions options)
        {
            return chunk.Payload.Open(reader =>
            {
                var placeholder = "decryption failed";

                // Read all items
                // 0: id
                var id = ReadItem(reader).ToUtf8();

                // 1: name
                var name = Util.DecryptAes256Plain(ReadItem(reader), encryptionKey, placeholder);

                // 2: group
                var group = Util.DecryptAes256Plain(ReadItem(reader), encryptionKey, placeholder);

                // 3: url
                var url = ReadItem(reader).ToUtf8().DecodeHexLoose().ToUtf8();

                // Ignore "group" accounts. They have no credentials.
                if (url == "http://group")
                    return null;

                // 4: extra (notes)
                var notes = Util.DecryptAes256Plain(ReadItem(reader), encryptionKey, placeholder);

                // 5: fav (is favorite)
                var isFavorite = ReadItem(reader).ToUtf8() == "1";

                // 6: sharedfromaid (?)
                SkipItem(reader);

                // 7: username
                var username = Util.DecryptAes256Plain(ReadItem(reader), encryptionKey, placeholder);

                // 8: password
                var password = Util.DecryptAes256Plain(ReadItem(reader), encryptionKey, placeholder);

                // 9: pwprotect (?)
                SkipItem(reader);

                // 10: genpw (?)
                SkipItem(reader);

                // 11: sn (is secure note)
                var secureNoteMarker = ReadItem(reader).ToUtf8();

                // Parse secure note
                if (options.ParseSecureNotesToAccount && secureNoteMarker == "1")
                {
                    var type = "";
                    ParseSecureNoteServer(notes, ref type, ref url, ref username, ref password);

                    // Only the some secure notes contain account-like information
                    if (!AllowedSecureNoteTypes.Contains(type))
                        return null;
                }

                // 12: last_touch_gmt (?)
                SkipItem(reader);

                // 13: autologin (?)
                SkipItem(reader);

                // 14: never_autofill (?)
                SkipItem(reader);

                // 15: realm (?)
                SkipItem(reader);

                // 16: id_again (?)
                SkipItem(reader);

                // 17: custom_js (?)
                SkipItem(reader);

                // 18: submit_id (?)
                SkipItem(reader);

                // 19: captcha_id (?)
                SkipItem(reader);

                // 20: urid (?)
                SkipItem(reader);

                // 21: basic_auth (?)
                SkipItem(reader);

                // 22: method (?)
                SkipItem(reader);

                // 23: action (?)
                SkipItem(reader);

                // 24: groupid (?)
                SkipItem(reader);

                // 25: deleted (?)
                SkipItem(reader);

                // 26: attachkey (?)
                SkipItem(reader);

                // 27: attachpresent (?)
                SkipItem(reader);

                // 28: individualshare (?)
                SkipItem(reader);

                // 29: notetype (?)
                SkipItem(reader);

                // 30: noalert (?)
                SkipItem(reader);

                // 31: last_modified_gmt (?)
                SkipItem(reader);

                // 32: hasbeenshared (?)
                SkipItem(reader);

                // 33: last_pwchange_gmt (?)
                SkipItem(reader);

                // 34: created_gmt (?)
                SkipItem(reader);

                // 35: vulnerable (?)
                SkipItem(reader);

                // 36: pwch (?)
                SkipItem(reader);

                // 37: breached (?)
                SkipItem(reader);

                // 38: template (?)
                SkipItem(reader);

                // 39: totp (?)
                var totp = Util.DecryptAes256Plain(ReadItem(reader), encryptionKey, placeholder);

                // 3 more left. Don't even bother skipping them.

                // 40: trustedHostnames (?)
                // 41: last_credential_monitoring_gmt (?)
                // 42: last_credential_monitoring_stat (?)

                // Adjust the path to include the group and the shared folder, if any.
                var path = MakeAccountPath(group, folder);

                return new Account(id: id,
                                   name: name,
                                   username: username,
                                   password: password,
                                   url: url,
                                   path: path,
                                   notes: notes,
                                   totp: totp,
                                   isFavorite: isFavorite,
                                   isShared: folder != null);
            });
        }

        public static SharedFolder Parse_SHAR(Chunk chunk, byte[] encryptionKey, RSAParameters rsaKey)
        {
            return chunk.Payload.Open(reader =>
            {
                // Id
                var id = ReadItem(reader).ToUtf8();

                // Key
                var rsaEncryptedFolderKey = ReadItem(reader);
                var key = Crypto.DecryptRsaSha1(rsaEncryptedFolderKey.ToUtf8().DecodeHex(), rsaKey)
                    .ToUtf8()
                    .DecodeHex();

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
                throw new InternalErrorException("Failed to decrypt private key");

            var pkcs8 = decrypted.Substring(header.Length,
                                            decrypted.Length - header.Length - footer.Length).DecodeHex();

            return Pem.ParsePrivateKeyPkcs8(pkcs8);
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

            return string.IsNullOrEmpty(group) ? folder.Name : $"{folder.Name}\\{group}";
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
