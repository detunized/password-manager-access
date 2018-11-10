// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Linq;

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

            return DecryptVault(encryptedVault, key);
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

        internal static Account[] DecryptVault(Response.Vault vault, byte[] key)
        {
            // By default use the derived key, this is true for some old vaults.
            var vaultKey = key;

            // The newer vaults have a key stored in the profile section. It's encrypted
            // with the derived key, with is effectively a KEK now.
            var encryptedVaultKey = vault.Profile.Key;
            if (encryptedVaultKey != null)
                vaultKey = DecryptToBytes(vault.Profile.Key, key);

            return vault.Ciphers
                .Where(i => i.Type == Response.CipherType.Login)
                .Select(i => ParseAccount(i, vaultKey)).ToArray();
        }

        internal static Account ParseAccount(Response.Cipher cipher, byte[] key)
        {
            return new Account(id: cipher.Id,
                               name: DecryptToStringOrBlank(cipher.Name, key),
                               username: DecryptToStringOrBlank(cipher.Login.Username, key),
                               password: DecryptToStringOrBlank(cipher.Login.Password, key),
                               url: DecryptToStringOrBlank(cipher.Login.Uri, key),
                               note: DecryptToStringOrBlank(cipher.Notes, key));
        }

        internal static byte[] DecryptToBytes(string s, byte[] key)
        {
            return CipherString.Parse(s).Decrypt(key);
        }

        internal static string DecryptToString(string s, byte[] key)
        {
            return  DecryptToBytes(s, key).ToUtf8();
        }

        // s may be null
        internal static string DecryptToStringOrBlank(string s, byte[] key)
        {
            return s == null ? "" : DecryptToString(s, key);
        }
    }
}
