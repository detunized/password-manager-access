// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.


using System.ComponentModel;
using Newtonsoft.Json;

namespace PasswordManagerAccess.ZohoVault.Response
{
    internal struct ResponseEnvelope<T>
    {
        [JsonProperty("operation", Required = Required.Always)]
        public readonly Operation<T> Operation;

        public T Payload => Operation.Details;
    }

    internal struct Operation<T>
    {
        [JsonProperty("name", Required = Required.Always)]
        public readonly string Name;

        [JsonProperty("result", Required = Required.Always)]
        public readonly Result Result;

        [JsonProperty("details", Required = Required.Always)]
        public readonly T Details;
    }

    internal struct Result
    {
        [JsonProperty("status", Required = Required.Always)]
        public readonly string Status;

        [JsonProperty("message", Required = Required.Always)]
        public readonly string Message;
    }

    internal struct AuthInfo
    {
        [JsonProperty("LOGIN", Required = Required.Always)]
        public readonly string KdfMethod;

        [JsonProperty("ITERATION", Required = Required.Always)]
        public readonly int Iterations;

        [JsonProperty("PASSPHRASE", Required = Required.Always)]
        public readonly string Passphrase;

        [JsonProperty("SALT", Required = Required.Always)]
        public readonly string Salt;
    }

    internal struct Vault
    {
        [JsonProperty("SECRETS", Required = Required.Always)]
        public readonly Secret[] Secrets;

        [JsonProperty("PRIVATEKEY", DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue("")]
        public readonly string PrivateKey;

        [JsonProperty("SHARINGKEY", DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue("")]
        public readonly string SharingKey;
    }

    internal struct Secret
    {
        [JsonProperty("SECRETID", Required = Required.Always)]
        public readonly string Id;

        [JsonProperty("SECRETNAME", Required = Required.Always)]
        public readonly string Name;

        [JsonProperty("SECRETURL", Required = Required.Always)]
        public readonly string Url;

        [JsonProperty("SECURENOTE", Required = Required.Always)]
        public readonly string Note;

        [JsonProperty("SECRETDATA", Required = Required.Always)]
        public readonly string Data;
    }

    internal struct SecretData
    {
        [JsonProperty("username", Required = Required.Always)]
        public readonly string Username;

        [JsonProperty("password", Required = Required.Always)]
        public readonly string Password;
    }
}
