// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using Newtonsoft.Json.Linq;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Kaspersky
{
    internal static class Parser
    {
        public static IEnumerable<Account> ParseVault(IEnumerable<Bosh.Change> db, byte[] encryptionKey)
        {
            var accounts = new List<Account>();
            var credentialsToParse = new List<Bosh.Change>();

            // Parse only the accounts first
            foreach (var item in db)
            {
                switch (item.Type)
                {
                case "Account":
                case "WebAccount":
                    accounts.Add(ParseAccount(item, encryptionKey));
                    break;
                case "Login":
                    credentialsToParse.Add(item);
                    break;
                }
            }

            // Parse the credentials and assign them to the account IDs
            var accountCredentials = new Dictionary<string, List<Credentials>>();
            foreach (var item in credentialsToParse)
            {
                var (ids, c) = ParseLogin(item, encryptionKey);
                foreach (var id in ids)
                    accountCredentials.GetOrAdd(id, () => new List<Credentials>()).Add(c);
            }

            // Assign credentials to the accounts
            foreach (var a in accounts)
                a.Credentials = accountCredentials.GetOrDefault(a.Id, null)?.ToArray() ?? new Credentials[0];

            return accounts;
        }

        internal static Account ParseAccount(Bosh.Change item, byte[] encryptionKey)
        {
            var (version, blob) = DecodeItem(item);
            return version switch
            {
                Version8 => ParseAccountVersion8(blob, encryptionKey),
                Version92 => ParseAccountVersion92(blob, encryptionKey),
                _ => throw new UnsupportedFeatureException($"Database item version {version} is not supported")
            };
        }

        internal static (string[], Credentials) ParseLogin(Bosh.Change item, byte[] encryptionKey)
        {
            var (version, blob) = DecodeItem(item);
            return version switch
            {
                Version8 => ParseLoginVersion8(blob, encryptionKey),
                Version92 => ParseLoginVersion92(blob, encryptionKey),
                _ => throw new UnsupportedFeatureException($"Database item version {version} is not supported")
            };
        }

        internal static (int, byte[]) DecodeItem(Bosh.Change item)
        {
            var blob = item.Data.Decode64();
            if (blob.Length < 4)
                throw CorruptedError("encrypted item is too short");

            return (blob[0], blob);
        }

        //
        // Version 8
        //

        internal static Account ParseAccountVersion8(byte[] blob, byte[] encryptionKey)
        {
            var json = DecryptBlobToJsonVersion8(blob, encryptionKey);

            return new Account(id: ConvertByteArrayToGuid(json.ArrayAtOrEmpty("guid")),
                               name: json.StringAt("name", ""),
                               url: json.StringAt("url", ""),
                               notes: json.StringAt("comment", ""),
                               new Credentials[0]);
        }

        internal static (string[], Credentials) ParseLoginVersion8(byte[] blob, byte[] encryptionKey)
        {
            var json = DecryptBlobToJsonVersion8(blob, encryptionKey);

            var accountIds = json.ArrayAtOrEmpty("accountlogins")
                .Select(x => ConvertByteArrayToGuid(x.ArrayAtOrEmpty("accountGuid")));

            var accountId = json.StringAt("accountGuid", "");
            if (!accountId.IsNullOrEmpty())
                accountIds = accountIds.Append(accountId);

            return (accountIds.ToArray(), new Credentials(id: ConvertByteArrayToGuid(json.ArrayAtOrEmpty("guid")),
                                                          name: json.StringAt("name", ""),
                                                          username: json.StringAt("login", ""),
                                                          password: json.StringAt("password", ""),
                                                          notes: json.StringAt("comment", "")));
        }

        internal static Dictionary<string, string> ParseItemVersion8(byte[] blob,
                                                                     byte[] encryptionKey,
                                                                     Dictionary<string, FieldInfoVersion8> fields)
        {
            var json = DecryptBlobVersion8(blob, encryptionKey);
            return ParseItemVersion8(json, fields);
        }

        internal static Dictionary<string, string> ParseItemVersion8(string json,
                                                                     Dictionary<string, FieldInfoVersion8> fields)
        {
            var item = JObject.Parse(json);
            var result = new Dictionary<string, string>(fields.Count);

            foreach (var field in fields)
            {
                var (name, info) = (field.Key, field.Value);
                if (item.ContainsKey(info.Name))
                {
                    result[name] = info.Type switch
                    {
                        FieldTypeVersion8.String => item.StringAt(info.Name, ""),
                        FieldTypeVersion8.Guid => ConvertByteArrayToGuid(item.ArrayAtOrEmpty(info.Name)),
                        _ => throw new InternalErrorException($"Unsupported field type {info.Type}"),
                    };
                }
            }

            return result;
        }

        internal static string ConvertByteArrayToGuid(JArray array)
        {
            return array.ToObject<byte[]>().ToHex();
        }

        internal static JObject DecryptBlobToJsonVersion8(byte[] blob, byte[] encryptionKey)
        {
            return JObject.Parse(DecryptBlobVersion8(blob, encryptionKey));
        }

        internal static string DecryptBlobVersion8(byte[] blob, byte[] encryptionKey)
        {
            if (blob.Length < 52)
                throw CorruptedError("encrypted item is too short");

            // Encrypted blob has a header of 52 bytes:
            // 4 bytes of version
            // 16 bytes of IV
            // 32 bytes of tag/MAC
            // The rest of the blob contains the ciphertext encrypted with AES-256-CBC with PKCS#7 padding.
            var iv = blob.Sub(4, 16);
            var storedTag = blob.Sub(20, 32);
            var ciphertext = blob.Sub(52, int.MaxValue);

            var plaintext = Crypto.DecryptAes256Cbc(ciphertext, iv, encryptionKey);

            // MAC for versions 9+ is calculated on the encrypted data
            // MAC for version 8 is calculated on the decrypted string
            // Look for `function E(e, t, n) {` for more info.
            var computedTag = Crypto.HmacSha256(plaintext, encryptionKey);
            if (!computedTag.SequenceEqual(storedTag))
                throw CorruptedError("tag doesn't match");

            return plaintext.ToUtf8();
        }

        //
        // Version 9.2
        //

        internal static Account ParseAccountVersion92(byte[] blob, byte[] encryptionKey)
        {
            var fields = ParseItemVersion92(blob, encryptionKey, AccountFieldsVersion92);

            return new Account(id: fields.GetOrDefault(FieldId, ""),
                               name: fields.GetOrDefault(FieldName, ""),
                               url: fields.GetOrDefault(FieldUrl, ""),
                               notes: fields.GetOrDefault(FieldNotes, ""),
                               credentials: new Credentials[0]);
        }

        internal static (string[], Credentials) ParseLoginVersion92(byte[] blob, byte[] encryptionKey)
        {
            var fields = ParseItemVersion92(blob, encryptionKey, LoginFieldsVersion92);
            var accountId = fields.GetOrDefault(FieldAccountId, "");
            var accountIds = accountId.IsNullOrEmpty() ? new string[0] : new[] {accountId};

            return (accountIds, new Credentials(id: fields.GetOrDefault(FieldId, ""),
                                                name: fields.GetOrDefault(FieldName, ""),
                                                username: fields.GetOrDefault(FieldUsername, ""),
                                                password: fields.GetOrDefault(FieldPassword, ""),
                                                notes: fields.GetOrDefault(FieldNotes, "")));
        }

        internal static Dictionary<string, string> ParseItemVersion92(byte[] blob, byte[] encryptionKey, string[] names)
        {
            if (blob.Length < 6)
                throw CorruptedError("encrypted item is too short");

            using var inputStream = new MemoryStream(blob, false);

            // Skip the item header:
            //   - version (4 bytes)
            //   - Zlib header (2 bytes)
            for (var i = 0; i < 6; i++)
                inputStream.ReadByte();

            using var deflateStream = new DeflateStream(inputStream, CompressionMode.Decompress);
            var decompressed = deflateStream.ReadAll();
            var json = decompressed.ToUtf8();

            return ParseItemVersion92(json, encryptionKey, names);
        }

        internal static Dictionary<string, string> ParseItemVersion92(string json, byte[] encryptionKey, string[] names)
        {
            var item = JObject.Parse(json);

            // Fields could be encrypted or not, this is defined by the field attributes.
            // The stored type of the field is ignored by the parser and it uses a hardcoded
            // table of known names and associated types. All our supported types are strings
            // and they are all seem to be encrypted. This makes things a lot easier. This
            // might change in the future.

            var fields = item.ArrayAtOrEmpty("fields");
            var fieldProperties = FindFieldByName(item.ArrayAtOrEmpty("attributes"), "propertiesMetadata")
                .ObjectAtOrEmpty("data")
                .ArrayAtOrEmpty("blob");

            var result = new Dictionary<string, string>(names.Length);
            foreach (var name in names)
            {
                // It's possible the field is not present at all.
                var field = FindFieldByName(fields, name);
                if (field == null)
                    continue;

                // It's also possible that its data is either null or blank.
                // When it's present but blank we're done. It cannot be encrypted.
                var fieldData = field.ObjectAtOrEmpty("data").StringAt("blob", null);
                if (fieldData.IsNullOrEmpty())
                {
                    result[name] = "";
                    continue;
                }

                var properties = FindFieldByName(fieldProperties, name);
                var isEncrypted = FindFieldByName(properties.ArrayAtOrEmpty("fields"), "isEncrypted")
                    .ObjectAtOrEmpty("data")
                    .BoolAt("blob", false);

                // If the field is not encrypted we use its data blob as is.
                // Otherwise it should a base64 encoded binary encrypted blob.
                result[name] = isEncrypted
                    ? DecryptBlobVersion92(fieldData.Decode64(), encryptionKey)
                    : fieldData;
            }

            return result;
        }

        internal static string DecryptBlobVersion92(byte[] blob, byte[] encryptionKey)
        {
            if (blob.Length < 48)
                throw CorruptedError("encrypted item is too short");

            // Encrypted blob has a header of 48 bytes:
            // 16 bytes of IV
            // 32 bytes of tag/MAC
            // The rest of the blob contains the ciphertext encrypted with AES-256-CBC with PKCS#7 padding.
            var iv = blob.Sub(0, 16);
            var storedTag = blob.Sub(16, 32);
            var ciphertext = blob.Sub(48, int.MaxValue);

            // MAC for versions 9+ is calculated on the encrypted data
            // MAC for version 8 is calculated on the decrypted string
            // Look for `function E(e, t, n) {` for more info.
            var computedTag = Crypto.HmacSha256(ciphertext, encryptionKey);
            if (!computedTag.SequenceEqual(storedTag))
                throw CorruptedError("tag doesn't match");

            var plaintext = Crypto.DecryptAes256Cbc(ciphertext, iv, encryptionKey);

            // For version 9.2 strings are stored in UTF-16. Otherwise it's UTF-8.
            return Encoding.BigEndianUnicode.GetString(plaintext);
        }

        internal static JToken FindFieldByName(JArray fields, string name)
        {
            return fields.FirstOrDefault(x => x.StringAt("name", "") == name);
        }

        internal static InternalErrorException CorruptedError(string message)
        {
            return new InternalErrorException($"Database is corrupted: {message}");
        }

        //
        // Data
        //

        public const int Version8 = 1;
        public const int Version9 = 2;
        public const int Version92 = 3;

        internal const string FieldId = "m_guid";
        internal const string FieldName = "m_name";
        internal const string FieldUrl = "m_url";
        internal const string FieldNotes = "m_comment";
        internal const string FieldAccountId = "m_account";
        internal const string FieldUsername = "m_login";
        internal const string FieldPassword = "m_password";

        internal enum FieldTypeVersion8
        {
            Guid,
            String,
        }

        internal struct FieldInfoVersion8
        {
            public readonly FieldTypeVersion8 Type;
            public readonly string Name;

            public FieldInfoVersion8(FieldTypeVersion8 type, string name)
            {
                Type = type;
                Name = name;
            }
        }

        // Maps version 8 fields to version 9.2
        internal static readonly Dictionary<string, FieldInfoVersion8> AccountFieldsVersion8 =
            new Dictionary<string, FieldInfoVersion8>
            {
                [FieldId] = new FieldInfoVersion8(FieldTypeVersion8.Guid, "guid"),
                [FieldName] = new FieldInfoVersion8(FieldTypeVersion8.String, "name"),
                [FieldUrl] = new FieldInfoVersion8(FieldTypeVersion8.String, "url"),
                [FieldNotes] = new FieldInfoVersion8(FieldTypeVersion8.String, "comment"),
            };

        // Maps version 8 fields to version 9.2
        internal static readonly Dictionary<string, FieldInfoVersion8> LoginFieldsVersion8 =
            new Dictionary<string, FieldInfoVersion8>
            {
                [FieldId] = new FieldInfoVersion8(FieldTypeVersion8.Guid, "guid"),
                [FieldAccountId] = new FieldInfoVersion8(FieldTypeVersion8.Guid, "accountGuid"),
                [FieldName] = new FieldInfoVersion8(FieldTypeVersion8.String, "name"),
                [FieldUsername] = new FieldInfoVersion8(FieldTypeVersion8.String, "login"),
                [FieldPassword] = new FieldInfoVersion8(FieldTypeVersion8.String, "password"),
                [FieldNotes] = new FieldInfoVersion8(FieldTypeVersion8.String, "comment"),
            };

        internal static readonly string[] AccountFieldsVersion92 =
        {
            FieldId,
            FieldName,
            FieldUrl,
            FieldNotes,
        };

        internal static readonly string[] LoginFieldsVersion92 =
        {
            FieldId,
            FieldAccountId,
            FieldName,
            FieldUsername,
            FieldPassword,
            FieldNotes,
        };

    }
}
