// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Bitwarden
{
    internal static class Client
    {
        public static Account[] OpenVault(string username, string password, IHttpClient http)
        {
            var jsonHttp = new JsonHttpClient(http, BaseUrl);

            // 1. Request the number of KDF iterations needed to derive the key
            var iterations = RequestKdfIterationCount(username, jsonHttp);

            // 2. Derive the master encryption key or KEK (key encryption key)
            var key = Crypto.DeriveKey(username, password, iterations);

            // 3. Hash the password that is going to be sent to the server
            var hash = Crypto.HashPassword(password, key);

            // 4. Authenticate with the server and get the token
            var token = RequestAuthToken(username, hash, jsonHttp);

            // 5. All subsequent requests are signed with this header
            var authJsonHttp = new JsonHttpClient(http,
                                                  BaseUrl,
                                                  new Dictionary<string, string> {{"Authorization", token}});

            // 6. Fetch the vault
            var encryptedVault = DownloadVault(authJsonHttp);

            return DecryptVault(encryptedVault, key);
        }

        //
        // Internal
        //

        internal static int RequestKdfIterationCount(string username, JsonHttpClient jsonHttp)
        {
            try
            {
                var response = jsonHttp.Post<Response.KdfInfo>("api/accounts/prelogin",
                                                               new Dictionary<string, string> {{"email", username}});

                // TODO: Check Kdf field and throw if it's not the one we support.
                return response.KdfIterations;
            }
            catch (ClientException e)
            {
                // The web client seems to ignore network errors. Default to 5000 iterations.
                if (IsHttp400To500(e))
                    return 5000;

                throw;
            }
        }

        internal static string RequestAuthToken(string username, byte[] passwordHash, JsonHttpClient jsonHttp)
        {
            try
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
            catch (ClientException e)
            {
                throw MakeSpecializedError(e);
            }
        }

        internal static Response.Vault DownloadVault(JsonHttpClient jsonHttp)
        {
            try
            {
                return jsonHttp.Get<Response.Vault>("api/sync");
            }
            catch (ClientException e)
            {
                throw MakeSpecializedError(e);
            }
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

            var folders = ParseFolders(vault.Folders, vaultKey);

            return vault.Ciphers
                .Where(i => i.Type == Response.ItemType.Login)
                .Select(i => ParseAccountItem(i, vaultKey, folders)).ToArray();
        }

        internal static Dictionary<string, string> ParseFolders(Response.Folder[] folders, byte[] key)
        {
            return folders.ToDictionary(i => i.Id, i => DecryptToString(i.Name, key));
        }

        internal static Account ParseAccountItem(Response.Item item, byte[] key, Dictionary<string, string> folders)
        {
            var folder = item.FolderId != null && folders.ContainsKey(item.FolderId)
                ? folders[item.FolderId]
                : "";

            return new Account(id: item.Id,
                               name: DecryptToStringOrBlank(item.Name, key),
                               username: DecryptToStringOrBlank(item.Login.Username, key),
                               password: DecryptToStringOrBlank(item.Login.Password, key),
                               url: DecryptToStringOrBlank(item.Login.Uri, key),
                               note: DecryptToStringOrBlank(item.Notes, key),
                               folder: folder);
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

        internal static HttpStatusCode? GetHttpStatus(ClientException e)
        {
            if (e.Reason != ClientException.FailureReason.NetworkError)
                return null;

            var we = e.InnerException as WebException;
            if (we == null || we.Status != WebExceptionStatus.ProtocolError)
                return null;

            var wr = we.Response as HttpWebResponse;
            if (wr == null)
                return null;

            return wr.StatusCode;
        }

        internal static bool IsHttp400To500(ClientException e)
        {
            var status = GetHttpStatus(e);
            return status != null && (int)status.Value / 100 == 4;
        }

        internal static string GetHttpResponse(ClientException e)
        {
            if (e.Reason != ClientException.FailureReason.NetworkError)
                return null;

            var we = e.InnerException as WebException;
            if (we == null || we.Status != WebExceptionStatus.ProtocolError)
                return null;

            var wr = we.Response as HttpWebResponse;
            if (wr == null)
                return null;

            var stream = wr.GetResponseStream();
            if (stream == null)
                return null;

            using (var r = new StreamReader(stream))
                return r.ReadToEnd();
        }

        internal static string GetServerErrorMessage(ClientException e)
        {
            var response = GetHttpResponse(e);
            if (response == null)
                return null;

            try
            {
                var parsed = JObject.Parse(response);
                return (string)(parsed["ErrorModel"] ?? parsed)["Message"];
            }
            catch (JsonException)
            {
                return null;
            }
        }

        internal static ClientException MakeSpecializedError(ClientException e)
        {
            if (!IsHttp400To500(e))
                return e;

            var message = GetServerErrorMessage(e);
            if (message == null)
                return e;

            return message.Contains("Username or password is incorrect")
                ? new ClientException(ClientException.FailureReason.IncorrectCredentials, message, e)
                : new ClientException(ClientException.FailureReason.RespondedWithError, message, e);
        }

        //
        // Private
        //

        private const string BaseUrl = "https://vault.bitwarden.com";
    }
}
