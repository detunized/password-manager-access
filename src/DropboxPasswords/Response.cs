// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

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
    }
}
