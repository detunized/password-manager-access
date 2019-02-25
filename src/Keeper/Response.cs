// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using Newtonsoft.Json;

namespace PasswordManagerAccess.Keeper.Response
{
    internal struct KdfInfo
    {
        [JsonProperty(PropertyName = "result")]
        public string Result;

        [JsonProperty(PropertyName = "result_code")]
        public string ResultCode;

        [JsonProperty(PropertyName = "message")]
        public string Message;

        [JsonProperty(PropertyName = "salt")]
        public string Salt;

        [JsonProperty(PropertyName = "iterations")]
        public int Iterations;
    }

    internal struct Session
    {
        [JsonProperty(PropertyName = "result")]
        public string Result;

        [JsonProperty(PropertyName = "result_code")]
        public string ResultCode;

        [JsonProperty(PropertyName = "message")]
        public string Message;

        [JsonProperty(PropertyName = "session_token")]
        public string Token;

        [JsonProperty(PropertyName = "keys")]
        public Keys Keys;
    }

    internal struct Keys
    {
        [JsonProperty(PropertyName = "encryption_params")]
        public string EncryptionParams;

        [JsonProperty(PropertyName = "encrypted_private_key")]
        public string EncryptPrivateKey;
    }

    internal struct EncryptedVault
    {
        [JsonProperty(PropertyName = "result")]
        public string Result;

        [JsonProperty(PropertyName = "full_sync")]
        public bool FullSync;

        [JsonProperty(PropertyName = "records")]
        public Record[] Records;

        [JsonProperty(PropertyName = "record_meta_data")]
        public RecordMeta[] RecordMeta;
    }

    internal struct Record
    {
        [JsonProperty(PropertyName = "record_uid")]
        public string Id;

        [JsonProperty(PropertyName = "data")]
        public string Data;
    }

    internal struct RecordMeta
    {
        [JsonProperty(PropertyName = "record_uid")]
        public string Id;

        [JsonProperty(PropertyName = "record_key")]
        public string Key;
    }

    internal struct RecordData
    {
        [JsonProperty(PropertyName = "title")]
        public string Name;

        [JsonProperty(PropertyName = "secret1")]
        public string Username;

        [JsonProperty(PropertyName = "secret2")]
        public string Password;

        [JsonProperty(PropertyName = "link")]
        public string Url;

        [JsonProperty(PropertyName = "notes")]
        public string Note;
    }
}
