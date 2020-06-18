// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using Newtonsoft.Json;

namespace PasswordManagerAccess.RoboForm.Response
{
    internal class ReceivedItems
    {
        [JsonProperty("accounts", Required = Required.Always)]
        public readonly SharedFolderInfo[] SharedFolders;
    }

    internal readonly struct SharedFolderInfo
    {
        [JsonProperty("accountId", Required = Required.Always)]
        public readonly string Id;

        [JsonProperty("name")]
        public readonly string Name;

        [JsonProperty("mp")]
        public readonly string EncryptedKey;
    }
}
