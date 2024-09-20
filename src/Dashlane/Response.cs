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

    internal class Blank { }

    internal readonly struct VerificationMethods
    {
        [JsonProperty("accountType", Required = Required.Always)]
        public readonly string AccountType;

        [JsonProperty("verifications", Required = Required.Always)]
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
        [JsonProperty("publicUserId", Required = Required.Always)]
        public readonly string UserId;

        [JsonProperty("deviceAccessKey", Required = Required.Always)]
        public readonly string AccessKey;

        [JsonProperty("deviceSecretKey", Required = Required.Always)]
        public readonly string SecretKey;

        [JsonProperty("serverKey")]
        public readonly string ServerKey;

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

    internal readonly struct ErrorEnvelope
    {
        [JsonProperty("requestId", Required = Required.Always)]
        public readonly string RequestId;

        [JsonProperty("errors", Required = Required.Always)]
        public readonly Error[] Errors;
    }

    internal readonly struct Error
    {
        [JsonProperty("type", Required = Required.Always)]
        public readonly string Type;

        [JsonProperty("code", Required = Required.Always)]
        public readonly string Code;

        [JsonProperty("message", Required = Required.Always)]
        public readonly string Message;
    }

    internal readonly struct FetchError
    {
        [JsonProperty("objectType", Required = Required.Always)]
        public readonly string Type;

        [JsonProperty("content", Required = Required.Always)]
        public readonly string Content;
    }

    internal class Vault
    {
        [JsonProperty(PropertyName = "fullBackupFile")]
        public readonly string EncryptedAccounts;

        [JsonProperty(PropertyName = "transactionList")]
        public readonly Transaction[] Transactions;

        //
        // These ones are not used and only needed to identify this data structure during de-serialization.
        //

        [JsonProperty(PropertyName = "timestamp", Required = Required.Always)]
        public readonly string UnusedTimestamp;

        [JsonProperty(PropertyName = "summary", Required = Required.Always)]
        public readonly object UnusedSummary;
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
