// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using Newtonsoft.Json;

namespace PasswordManagerAccess.Dashlane.Response
{
    internal class Envelope<T>
    {
        [JsonProperty("requestId", Required = Required.Always)]
        public readonly string RequestId;

        [JsonProperty("data", Required = Required.Always)]
        public readonly T Data;
    }

    internal readonly struct VerificationMethods
    {
        [JsonProperty("verification", Required = Required.Always)]
        public readonly VerificationMethod[] Methods;
    }

    internal readonly struct VerificationMethod
    {
        [JsonProperty("type", Required = Required.Always)]
        public readonly string Name;
    }

    internal readonly struct AuthTicket
    {
        [JsonProperty("authTicket", Required = Required.Always)]
        public readonly string Ticket;
    }

    internal readonly struct DeviceInfo
    {
        [JsonProperty("deviceAccessKey", Required = Required.Always)]
        public readonly string AccessKey;

        [JsonProperty("deviceSecretKey", Required = Required.Always)]
        public readonly string SecretKey;

        [JsonProperty("publicUserId", Required = Required.Always)]
        public readonly string UserId;

        // TODO: Make this required
        [JsonProperty("sharingKeys", Required = Required.Default)]
        public readonly SharingKeys SharingKeys;
    }

    internal readonly struct SharingKeys
    {
        // TODO: Make this required
        [JsonProperty("publicKey", Required = Required.Default)]
        public readonly string PublicKey;

        // TODO: Make this required
        [JsonProperty("privateKey", Required = Required.Default)]
        public readonly string PrivateKey;
    }

    internal struct ErrorEnvelope
    {
        [JsonProperty("requestId", Required = Required.Always)]
        public readonly string RequestId;

        [JsonProperty("errors", Required = Required.Always)]
        public readonly Error[] Errors;
    }

    internal struct Error
    {
        [JsonProperty("type", Required = Required.Always)]
        public readonly string Type;

        [JsonProperty("code", Required = Required.Always)]
        public readonly string Code;

        [JsonProperty("message", Required = Required.Always)]
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
