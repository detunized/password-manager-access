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
        public static IEnumerable<Account> ParseVault(IEnumerable<Bosh.Change> db)
        {
            var accounts = new List<Dictionary<string, string>>();
            var credentials = new List<Dictionary<string, string>>();

            // Parse all the relevant items into temporary ad-hoc structures
            foreach (var item in db)
            {
                switch (item.Type)
                {
                case "WebAccount":
                    accounts.Add(ParseWebAccount(item));
                    break;
                case "Login":
                    credentials.Add(ParseLogin(item));
                    break;
                }
            }

            // Theoretically it's possible that some entries have their account ID missing. They will end
            // end up grouped under the blank ("") key. We just ignore those, should they appear in the vault.
            // They are basically orphans with no account to be attached to.
            var credentialsByAccount = credentials.ToLookup(x => x.GetOrDefault(FieldAccountId, ""));

            // Convert to the final objects by grouping the logins (Credentials)
            // under the corresponding web accounts (Account).
            return accounts.Select(account =>
            {
                var id = account.GetOrDefault(FieldId, "");


                var accountCredentials = credentialsByAccount[id].Select(
                    c => new Credentials(c.GetOrDefault(FieldId, ""),
                                         c.GetOrDefault(FieldName, ""),
                                         c.GetOrDefault(FieldUsername, ""),
                                         c.GetOrDefault(FieldPassword, ""),
                                         c.GetOrDefault(FieldNotes, "")));

                return new Account(id,
                                   account.GetOrDefault(FieldName, ""),
                                   account.GetOrDefault(FieldUrl, ""),
                                   account.GetOrDefault(FieldNotes, ""),
                                   accountCredentials.ToArray());
            });
        }

        internal static Dictionary<string, string> ParseWebAccount(Bosh.Change item)
        {
            var (version, blob) = DecodeItem(item);
            return version switch
            {
                Version92 => ParseItemVersion92(blob, AccountFields),
                _ => throw new UnsupportedFeatureException($"Database item version {version} is not supported")
            };
        }

        internal static Dictionary<string, string> ParseLogin(Bosh.Change item)
        {
            var (version, blob) = DecodeItem(item);
            return version switch
            {
                Version92 => ParseItemVersion92(blob, LoginFields),
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

        internal static Dictionary<string, string> ParseItemVersion92(byte[] blob, params string[] names)
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

            return ParseItemVersion92(json, names);
        }

        internal static Dictionary<string, string> ParseItemVersion92(string json, params string[] names)
        {
            var item = JObject.Parse(json);

            // Field types:
            //
            // 0: "Text"
            // 1: "Number"
            // 2: "Boolean"
            // 3: "Blob"
            // 4: "Real"
            // 5: "Json"
            //
            // Text: 0
            // Number: 1
            // Boolean: 2
            // Blob: 3
            // Real: 4
            // Json: 5

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
                var fieldData = field.ObjectAtOrEmpty("data").StringAt("blob", null);
                if (fieldData == null)
                    continue;

                // When it's present but blank we're done. It cannot be encrypted.
                if (fieldData.Length == 0)
                {
                    result[name] = "";
                    continue;
                }

                var properties = FindFieldByName(fieldProperties, name);
                var isEncrypted = FindFieldByName(properties.ArrayAtOrEmpty("fields"), "isEncrypted")
                    .ObjectAtOrEmpty("data")
                    .BoolAt("blob", false);

                // If the field is not encrypted we use its data blob as is.
                if (!isEncrypted)
                {
                    result[name] = fieldData;
                    continue;
                }

                // Otherwise it should a base64 encoded binary encrypted blob.
                var blob = fieldData.Decode64();

                // Encrypted blob has a header of 12 words (48 bytes)
                // 16 bytes of IV
                // 32 bytes of tag/MAC
                // The rest of the blob contains the ciphertext encrypted with AES-256-CBC with PKCS#7 padding.
                var iv = blob.Sub(0, 16);
                var tag = blob.Sub(16, 32);
                var ciphertext = blob.Sub(48, int.MaxValue);

                // TODO: Verify tag/MAC
                // MAC for versions 9+ is calculated on the encrypted data
                // MAC for version 8 is calculated on the decrypted string
                // Look for `function E(e, t, n) {` for more info.

                // TODO: Pass this in
                var key = "d8f2bfe4980d90e3d402844e5332859ecbda531ab24962d2fdad4d39ad98d2f9".DecodeHex();

                var plaintext = Crypto.DecryptAes256Cbc(ciphertext, iv, key);

                // For version 9.2 strings are stored in UTF-16. Otherwise it's UTF-8.
                result[name] = Encoding.BigEndianUnicode.GetString(plaintext);
            }

            return result;
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

        internal static readonly string[] AccountFields =
        {
            FieldId,
            FieldName,
            FieldUrl,
            FieldNotes,
        };

        internal static readonly string[] LoginFields =
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
