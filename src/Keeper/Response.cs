// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using Newtonsoft.Json;

namespace PasswordManagerAccess.Keeper.Response
{
    internal class Status
    {
        [JsonProperty(PropertyName = "result")]
        public readonly string Result;

        [JsonProperty(PropertyName = "result_code")]
        public readonly string ResultCode;

        [JsonProperty(PropertyName = "message")]
        public readonly string Message;

        public bool Failed => Result != "success";
    }

    internal class KdfInfo: Status
    {
        [JsonProperty(PropertyName = "salt")]
        public readonly string Salt;

        [JsonProperty(PropertyName = "iterations")]
        public readonly int Iterations;
    }

    internal class Session: Status
    {
        [JsonProperty(PropertyName = "session_token")]
        public readonly string Token;

        [JsonProperty(PropertyName = "keys")]
        public readonly Keys Keys;
    }

    internal struct Keys
    {
        [JsonProperty(PropertyName = "encryption_params")]
        public readonly string EncryptionParams;

        [JsonProperty(PropertyName = "encrypted_private_key")]
        public readonly string EncryptPrivateKey;
    }

    internal class EncryptedVault: Status
    {
        [JsonProperty(PropertyName = "full_sync")]
        public readonly bool FullSync;

        [JsonProperty(PropertyName = "records")]
        public readonly Record[] Records;

        [JsonProperty(PropertyName = "record_meta_data")]
        public readonly RecordMeta[] RecordMeta;
    }

    internal struct Record
    {
        [JsonProperty(PropertyName = "record_uid")]
        public readonly string Id;

        [JsonProperty(PropertyName = "data")]
        public readonly string Data;
    }

    internal struct RecordMeta
    {
        [JsonProperty(PropertyName = "record_uid")]
        public readonly string Id;

        [JsonProperty(PropertyName = "record_key")]
        public readonly string Key;
    }

    internal struct RecordData
    {
        [JsonProperty(PropertyName = "title")]
        public readonly string Name;

        [JsonProperty(PropertyName = "secret1")]
        public readonly string Username;

        [JsonProperty(PropertyName = "secret2")]
        public readonly string Password;

        [JsonProperty(PropertyName = "link")]
        public readonly string Url;

        [JsonProperty(PropertyName = "notes")]
        public readonly string Note;
    }
}
