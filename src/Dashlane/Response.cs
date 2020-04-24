// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using Newtonsoft.Json;

namespace PasswordManagerAccess.Dashlane.Response
{
    internal class LoginType
    {
        [JsonProperty(PropertyName = "exists", Required = Required.Always)]
        public readonly string Exists;
    }

    internal class Status
    {
        [JsonProperty(PropertyName = "code", Required = Required.Always)]
        public readonly int Code;

        [JsonProperty(PropertyName = "message", Required = Required.Always)]
        public readonly string Message;
    }

    internal class Vault
    {
        [JsonProperty(PropertyName = "token")]
        public readonly string Token;

        [JsonProperty(PropertyName = "serverKey")]
        public readonly string ServerKey;

        [JsonProperty(PropertyName = "fullBackupFile")]
        public readonly string EncryptedAccounts;

        [JsonProperty(PropertyName = "transactionList")]
        public readonly Transaction[] Transactions;

        // This one is not used and is only used to identify this data structure during de-serialization.
        [JsonProperty(PropertyName = "timestamp", Required = Required.Always)]
        public readonly string Timestamp;

        // This one is not used and is only used to identify this data structure during de-serialization.
        [JsonProperty(PropertyName = "summary", Required = Required.Always)]
        public readonly object Summary;
    }

    internal class Transaction
    {
        [JsonProperty(PropertyName = "type")]
        public readonly string Kind;

        [JsonProperty(PropertyName = "action")]
        public readonly string Action;

        [JsonProperty(PropertyName = "content")]
        public readonly string Content;

        [JsonProperty(PropertyName = "identifier")]
        public readonly string Id;
    }
}
