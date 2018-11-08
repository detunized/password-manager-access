// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;

namespace Bitwarden
{
    public static class Client
    {
        public static Account[] OpenVault(string username, string password, IHttpClient http)
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

            // TODO: Implement this
            return new Account[0];
        }

        //
        // Internal
        //

        internal static Response.Vault DownloadVault(JsonHttpClient jsonHttp)
        {
            return jsonHttp.Get<Response.Vault>("api/sync");
        }

        internal static int RequestKdfIterationCount(string username, JsonHttpClient jsonHttp)
        {
            var response = jsonHttp.Post<Response.KdfInfo>("api/accounts/prelogin",
                                                           new Dictionary<string, string> {{"email", username}});

            // TODO: Check Kdf field and throw if it's not the one we support.
            return response.KdfIterations;
        }

        internal static string RequestAuthToken(string username, byte[] passwordHash, JsonHttpClient jsonHttp)
        {
            var response = jsonHttp.PostForm<Response.AuthToken>("identity/connect/token",
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
    }
}
