// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
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

        [JsonProperty("ISSHARED", DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue("")]
        public readonly string IsShared;
    }

    internal struct SecretData
    {
        [JsonProperty("username", Required = Required.Always)]
        public readonly string Username;

        [JsonProperty("password", Required = Required.Always)]
        public readonly string Password;
    }

    internal class Lookup
    {
        [JsonProperty("status_code", Required = Required.Always)]
        public readonly int StatusCode;

        [JsonProperty("message", DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue("")]
        public readonly string Message;

        [JsonProperty("lookup")]
        public readonly LookupResult Result;

        [JsonProperty("errors")]
        public readonly LookupError[] Errors;

        [JsonProperty("data")]
        public readonly LookupRedirect Redirect;
    }

    internal class LookupResult
    {
        [JsonProperty("loginid", Required = Required.Always)]
        public readonly string Username;

        [JsonProperty("dc", Required = Required.Always)]
        public readonly string DataCenter;
    }

    internal class LookupError
    {
        [JsonProperty("code", Required = Required.Always)]
        public readonly string Code;
    }

    internal class LookupRedirect
    {
        [JsonProperty("redirect_uri", DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue("")]
        public readonly string RedirectUrl;

        [JsonProperty("dc", DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue("")]
        public readonly string DataCenter;
    }
}
