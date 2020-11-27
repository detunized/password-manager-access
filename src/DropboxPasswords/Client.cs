// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System;
using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json;
using PasswordManagerAccess.Common;
using R = PasswordManagerAccess.DropboxPasswords.Response;

namespace PasswordManagerAccess.DropboxPasswords
{
    internal static class Client
    {
        public static Account[] OpenVault(string oauthToken, string[] recoveryWords, IRestTransport transport)
        {
            // We do this first to fail early in case the recovery words are incorrect.
            var masterKey = Util.DeriveMasterKeyFromRecoveryWords(recoveryWords);

            var rest = new RestClient(transport,
                                      "https://api.dropboxapi.com/2",
                                      defaultHeaders: new Dictionary<string, string>
                                      {
                                          ["Authorization"] = $"Bearer {oauthToken}"
                                      });

            // 1. Get account info
            var accountInfo = Post<R.AccountInfo>("users/get_current_account",
                                                  RestClient.JsonNull, // Important to send null!
                                                  RestClient.NoHeaders,
                                                  rest);
            if (accountInfo.Disabled)
                throw new InternalErrorException($"The account is disabled");

            // 2. Get features
            var features = Post<R.Features>("passwords/get_features_v2",
                                            RestClient.JsonNull, // Important to send null!
                                            RestClient.NoHeaders,
                                            rest);
            if (features.Eligibility.Tag != "enabled")
                throw new InternalErrorException("Dropbox Passwords is not enabled on this account");

            // 3. List the root folder
            // TODO: Very long folders are not supported. See "has_more" and "cursor".
            var rootFolder = Post<R.RootFolder>("files/list_folder",
                                                new Dictionary<string, object> {["path"] = ""},
                                                MakeRootPathHeaders(features.Eligibility.RootPath),
                                                rest);

            // 4. Get all entries
            var contentRest = new RestClient(rest.Transport,
                                             "https://content.dropboxapi.com/2",
                                             defaultHeaders: rest.DefaultHeaders);
            var entries = DownloadAllEntries(rootFolder, features.Eligibility.RootPath, contentRest);

            // Try to find all keysets that decrypt (normally there's only one).
            var keysets = FindAndDecryptAllKeysets(entries, masterKey);

            // Try to decrypt all account entries and see what decrypts.
            var accounts = FindAndDecryptAllAccounts(entries, keysets);

            // Done, phew!
            return accounts;
        }

        //
        // Internal
        //

        internal static R.EncryptedEntry[] DownloadAllEntries(R.RootFolder rootFolder,
                                                              string rootPath,
                                                              RestClient contentRest)
        {
            return rootFolder.Entries
                .AsParallel() // Download in parallel
                .Where(e => e.IsDownloadable && e.Tag == "file")
                .Select(e => DownloadFolderEntry(e.Path, rootPath, contentRest))
                .ToArray(); // This will force the actual download
        }

        internal static R.Keyset[] FindAndDecryptAllKeysets(R.EncryptedEntry[] entries, byte[] masterKey)
        {
            return entries
                .Where(e => e.Type == "keyset")
                .Select(e => DecryptKeyset(e, masterKey))
                .ToArray();
        }

        internal static Account[] FindAndDecryptAllAccounts(R.EncryptedEntry[] entries, R.Keyset[] keysets)
        {
            var keys = ExtractAllKeys(keysets);
            return entries
                .Where(e => e.Type == "password")
                .SelectMany(e => DecryptAccounts(e, keys))
                .ToArray();
        }

        internal static IEnumerable<Account> DecryptAccounts(R.EncryptedEntry entry, Dictionary<string, byte[]> keys)
        {
            // Important: key lookup must be case insensitive! There's a case mismatch in the parsed JSON.
            if (!keys.TryGetValue(entry.Id.ToLower(), out var key))
                return Array.Empty<Account>();

            var folder = DecryptVaultFolder(entry, key);
            return folder.Items
                .Where(x => !x.IsDeleted)
                .Select(x => new Account(id: x.Id ?? "",
                                         name: x.Name ?? "",
                                         username: x.Username ?? "",
                                         password: x.Password ?? "",
                                         url: x.Url ?? "",
                                         note: x.Note ?? "",
                                         folder: folder.Name ?? ""));
        }

        internal static Dictionary<string, byte[]> ExtractAllKeys(R.Keyset[] keysets)
        {
            // Important: the keys must be lowercased! There's a case mismatch in the parsed JSON.
            return keysets
                .SelectMany(ks => ks.Keys.Select(k => (k.Key, k.Value.KeyBase64)))
                .ToDictionary(x => x.Key.ToLower(), x => x.KeyBase64.Decode64());
        }

        //
        // Network
        //

        internal static R.EncryptedEntry DownloadFolderEntry(string path, string rootPath, RestClient rest)
        {
            var headers = MakeRootPathHeaders(rootPath).MergeCopy(new Dictionary<string, string>
            {
                ["Dropbox-API-Arg"] = $"{{\"path\":\"{path}\"}}"
            });

            var response = rest.PostRaw("files/download", "", headers);
            if (!response.IsSuccessful)
                throw MakeError(response);

            return Deserialize<R.EncryptedEntry>(response.Content);
        }

        internal static Dictionary<string, string> MakeRootPathHeaders(string rootPath)
        {
            return new Dictionary<string, string>
            {
                ["Dropbox-API-Path-Root"] = $"{{\".tag\":\"namespace_id\",\"namespace_id\":\"{rootPath}\"}}"
            };
        }

        internal static T Post<T>(string endpoint,
                                  Dictionary<string, object> parameters,
                                  Dictionary<string, string> headers,
                                  RestClient rest)
        {
            var response = rest.PostJson<T>(endpoint: endpoint,
                                            parameters: parameters,
                                            headers: headers);
            if (!response.IsSuccessful)
                throw MakeError(response);

            return response.Data;
        }

        //
        // Crypto
        //

        internal static R.Keyset DecryptKeyset(R.EncryptedEntry entry, byte[] key)
        {
            return Deserialize<R.Keyset>(Decrypt(entry.EncryptedBundle, key));
        }

        internal static R.VaultFolder DecryptVaultFolder(R.EncryptedEntry entry, byte[] key)
        {
            return Deserialize<R.VaultFolder>(Decrypt(entry.EncryptedBundle, key));
        }

        internal static byte[] Decrypt(R.EncryptedBundle encrypted, byte[] key)
        {
            return Crypto.DecryptXChaCha20Poly1305(encrypted.CiphertextBase64.Decode64(),
                                                   encrypted.NonceBase64.Decode64(),
                                                   key);
        }

        internal static T Deserialize<T>(byte[] json)
        {
            return Deserialize<T>(json.ToUtf8());
        }

        internal static T Deserialize<T>(string json)
        {
            try
            {
                return JsonConvert.DeserializeObject<T>(json);
            }
            catch (JsonException e)
            {
                throw MakeError($"Failed to deserialize {typeof(T)} from JSON in response", e);
            }
        }

        //
        // Errors
        //

        internal static InternalErrorException MakeError(RestResponse response)
        {
            return MakeError($"POST request to {response.RequestUri} failed");
        }

        internal static InternalErrorException MakeError(string message, Exception? inner = null)
        {
            return new InternalErrorException(message, inner);
        }
    }
}
