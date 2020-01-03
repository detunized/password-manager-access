// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using Newtonsoft.Json;

namespace PasswordManagerAccess.OnePassword.Response
{
    internal class NewSession
    {
        [JsonProperty(PropertyName = "status", Required = Required.Always)]
        public readonly string Status;

        [JsonProperty(PropertyName = "sessionID", Required = Required.Always)]
        public readonly string SessionId;

        [JsonProperty(PropertyName = "accountKeyFormat")]
        public readonly string KeyFormat;

        [JsonProperty(PropertyName = "accountKeyUuid")]
        public readonly string KeyUuid;

        [JsonProperty(PropertyName = "userAuth")]
        public readonly UserAuth Auth;
    }

    internal struct UserAuth
    {
        [JsonProperty(PropertyName = "method")]
        public readonly string Method;

        [JsonProperty(PropertyName = "alg")]
        public readonly string Algorithm;

        [JsonProperty(PropertyName = "iterations")]
        public readonly int Iterations;

        [JsonProperty(PropertyName = "salt")]
        public readonly string Salt;
    }

    internal struct SuccessStatus
    {
        [JsonProperty(PropertyName = "success", Required = Required.Always)]
        public readonly int Success;
    }
}
