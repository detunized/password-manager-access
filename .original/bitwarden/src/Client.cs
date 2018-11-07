// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using Newtonsoft.Json;

namespace Bitwarden
{
    public static class Client
    {
        public static void OpenVault(string username, string password, IHttpClient http)
        {
            var jsonHttp = new JsonHttpClient(http, "https://vault.bitwarden.com");

            // 1. Request the number of KDF iterations needed to derive the key
            var iterations = RequestKdfIterationCount(username, jsonHttp);

            // 2. Derive the master encryption key or KEK (key encryption key)
            var key = Crypto.DeriveKey(username, password, iterations);

            // 3. Hash the password that is going to be sent to the server
            var hash = Crypto.HashPassword(password, key);

            // 4. Authenticate with the server and get the token
            var token = RequestAuthToken(username, hash, jsonHttp);

            // 5. All subsequent requests are signed with this header
            jsonHttp.Headers["Authorization"] = token;

            // 6. Fetch the vault
            var encryptedVault = DownloadVault(jsonHttp);
        }

        internal static VaultResponse DownloadVault(JsonHttpClient jsonHttp)
        {
            return jsonHttp.Get<VaultResponse>("api/sync");
        }

        internal static int RequestKdfIterationCount(string username, JsonHttpClient jsonHttp)
        {
            var response = jsonHttp.Post<KdfResponse>("api/accounts/prelogin",
                                                      new Dictionary<string, string> {{"email", username}});

            // TODO: Check Kdf field and throw if it's not the one we support.
            return response.KdfIterations;
        }

        internal static string RequestAuthToken(string username, byte[] passwordHash, JsonHttpClient jsonHttp)
        {
            var response = jsonHttp.PostForm<AuthTokenResponse>("identity/connect/token",
                                                                new Dictionary<string, string>
                                                                {
                                                                    {"username", username},
                                                                    {"password", passwordHash.ToBase64()},
                                                                    {"grant_type", "password"},
                                                                    {"scope", "api offline_access"},
                                                                    {"client_id", "web"},
                                                                });
            return string.Format("{0} {1}", response.TokenType, response.AccessToken);
        }

        //
        // Internal
        //

        // TODO: Move all of these out of here. Maybe?

        [JsonObject(ItemRequired = Required.Always)]
        internal struct KdfResponse
        {
            public int Kdf;
            public int KdfIterations;
        }

        [JsonObject(ItemRequired = Required.Always)]
        internal struct AuthTokenResponse
        {
            [JsonProperty(PropertyName = "token_type")]
            public string TokenType;
            [JsonProperty(PropertyName = "access_token")]
            public string AccessToken;
        }

        [JsonObject(ItemRequired = Required.Always)]
        internal struct VaultResponse
        {
            public ProfileModel Profile;
            public CipherModel[] Ciphers;
        }

        internal struct ProfileModel
        {
            public string Key;
        }

        internal struct CipherModel
        {
            [JsonProperty(Required = Required.Always)]
            public string Id;
            public string Name;
            public string Notes;
            public LoginModel Login;
        }

        internal struct LoginModel
        {
            public string Username;
            public string Password;
            public string Uri;
        }
    }
}
