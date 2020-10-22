// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System;
using Newtonsoft.Json;

namespace PasswordManagerAccess.DropboxPasswords
{
    internal static class Response
    {
        public class AccountInfo
        {
            [JsonProperty("account_id", Required = Required.Always)]
            public readonly string AccountId;

            [JsonProperty("email", Required = Required.Always)]
            public readonly string Email;

            [JsonProperty("disabled", Required = Required.Always)]
            public readonly bool Disabled;

            // Mutes the uninitialized non-nullable field warnings
            private AccountInfo()
            {
                AccountId = "";
                Email = "";
            }
        }

        public class Features
        {
            [JsonProperty("eligibility", Required = Required.Always)]
            public readonly Eligibility Eligibility;
        }

        public readonly struct Eligibility
        {
            [JsonProperty(".tag", Required = Required.Always)]
            public readonly string Tag;

            [JsonProperty("passwords_path_root", Required = Required.Always)]
            public readonly string RootPath;
        }

        public class RootFolder
        {
            [JsonProperty("entries", Required = Required.Always)]
            public readonly FolderEntry[] Entries;

            [JsonProperty("cursor", Required = Required.Always)]
            public readonly string Cursor;

            [JsonProperty("has_more", Required = Required.Always)]
            public readonly bool HasMore;

            // Mutes the uninitialized non-nullable field warnings
            private RootFolder()
            {
                Entries = Array.Empty<FolderEntry>();
                Cursor = "";
            }
        }

        public readonly struct FolderEntry
        {
            [JsonProperty(".tag", Required = Required.Always)]
            public readonly string Tag;

            [JsonProperty("path_lower", Required = Required.Always)]
            public readonly string Path;

            [JsonProperty("is_downloadable", Required = Required.Always)]
            public readonly bool IsDownloadable;
        }

        public class EncryptedEntry
        {
            [JsonProperty("identifier", Required = Required.Always)]
            public readonly string Id;

            [JsonProperty("type", Required = Required.Always)]
            public readonly string Type;

            [JsonProperty("version", Required = Required.Always)]
            public readonly int Version;

            [JsonProperty("encryptedBundle", Required = Required.Always)]
            public readonly EncryptedBundle EncryptedBundle;

            // Mutes the uninitialized non-nullable field warnings
            private EncryptedEntry()
            {
                Id = "";
                Type = "";
            }
        }

        internal readonly struct EncryptedBundle
        {
            [JsonProperty("base64EncryptedData", Required = Required.Always)]
            public readonly string CiphertextBase64;

            [JsonProperty("base64Nonce", Required = Required.Always)]
            public readonly string NonceBase64;
        }
    }
}
