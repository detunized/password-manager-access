// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.


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
}
