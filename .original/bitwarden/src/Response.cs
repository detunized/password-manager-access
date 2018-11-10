// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using Newtonsoft.Json;

namespace Bitwarden
{
    internal static class Response
    {
        [JsonObject(ItemRequired = Required.Always)]
        internal struct KdfInfo
        {
            public int Kdf;
            public int KdfIterations;
        }

        [JsonObject(ItemRequired = Required.Always)]
        internal struct AuthToken
        {
            [JsonProperty(PropertyName = "token_type")]
            public string TokenType;
            [JsonProperty(PropertyName = "access_token")]
            public string AccessToken;
        }

        [JsonObject(ItemRequired = Required.Always)]
        internal struct Vault
        {
            public Profile Profile;
            public Cipher[] Ciphers;
        }

        internal struct Profile
        {
            public string Key;
        }

        internal struct Cipher
        {
            [JsonProperty(Required = Required.Always)]
            public string Id;
            [JsonProperty(Required = Required.Always)]
            public int Type;
            public string Name;
            public string Notes;
            public Login Login;
        }

        internal struct Login
        {
            public string Username;
            public string Password;
            public string Uri;
        }
    }
}
