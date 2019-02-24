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
    }

    internal struct EncryptedVault
    {
        [JsonProperty(PropertyName = "result")]
        public string Result;

        [JsonProperty(PropertyName = "full_sync")]
        public bool FullSync;
    }
}
