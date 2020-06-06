// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using Newtonsoft.Json;

namespace PasswordManagerAccess.OpVault.Model
{
    internal class Profile
    {
        [JsonProperty("salt", Required = Required.Always)]
        public readonly string Salt;

        [JsonProperty("iterations", Required = Required.Always)]
        public readonly int Iterations;

        [JsonProperty("masterKey", Required = Required.Always)]
        public readonly string MasterKey;

        [JsonProperty("overviewKey", Required = Required.Always)]
        public readonly string OverviewKey;
    }

}
