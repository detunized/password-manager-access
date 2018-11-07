// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using Newtonsoft.Json;

namespace Bitwarden
{
    public static class Client
    {
        // Returns the auth token
        public static string Login(string username, string password, IHttpClient http)
        {
            var jsonHttp = new JsonHttpClient(http, "https://vault.bitwarden.com");
            var iterations = RequestKdfIterationCount(username, jsonHttp);
            var key = Crypto.DeriveKey(username, password, iterations);
            var hash = Crypto.HashPassword(password, key);
            var token = RequestAuthToken(username, hash, jsonHttp);

            return token;
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
    }
}
