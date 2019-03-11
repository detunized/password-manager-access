// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Keeper
{
    using R = Response;

    internal static class Client
    {
        public static Account[] OpenVault(string username, string password, IHttpClient http)
        {
            var jsonHttp = new JsonHttpClient(http, "https://keepersecurity.com/api/v2/");
            var kdfInfo = RequestKdfInfo(username, jsonHttp);
            var passwordHash = Crypto.HashPassword(password,
                                                   kdfInfo.Salt.Decode64Loose(),
                                                   kdfInfo.Iterations);
            var session = Login(username, passwordHash, jsonHttp);
            var encryptedVault = RequestVault(username, session.Token, jsonHttp);
            var vaultKey = DecryptVaultKey(session, password);
            var accounts = DecryptVault(encryptedVault, vaultKey);

            return accounts;
        }

        //
        // Internal
        //

        internal static R.KdfInfo RequestKdfInfo(string username, JsonHttpClient jsonHttp)
        {
            var response = jsonHttp.Post<R.KdfInfo>("", SharedLoginParameters(username));

            // This is a special case. It responds with failure and it's ok.
            if (response.Failed && response.ResultCode == "auth_failed")
                return response;

            throw MakeError(response, "KDF info");
        }

        internal static R.Session Login(string username, byte[] passwordHash, JsonHttpClient jsonHttp)
        {
            var parameters = SharedLoginParameters(username);
            parameters["auth_response"] = passwordHash.ToUrlSafeBase64NoPadding();

            var response = jsonHttp.Post<R.Session>("", parameters);
            if (response.Failed)
                throw MakeError(response, "login");

            return response;
        }

        internal static Dictionary<string, object> SharedLoginParameters(string username)
        {
            return new Dictionary<string, object>
            {
                {"command", "login"},
                {"include", new []{"keys"}},
                {"version", 2},
                {"client_version", ClientVersion},
                {"username", username},
            };
        }

        internal static R.EncryptedVault RequestVault(string username, string token, JsonHttpClient jsonHttp)
        {
            var response = jsonHttp.Post<R.EncryptedVault>("", new Dictionary<string, object>
            {
                {"command", "sync_down"},
                {"include", new []{"sfheaders", "sfrecords", "sfusers", "teams", "folders"}},
                {"revision", 0},
                {"client_time", GetCurrentTimeInMs()},
                {"device_id", "Commander"},
                {"device_name", "Commander"},
                {"protocol_version", 1},
                {"client_version", ClientVersion},
                {"session_token", token},
                {"username", username},
            });

            if (response.Failed)
                throw MakeError(response, "vault");

            if (!response.FullSync)
                throw new UnsupportedFeatureException("Partial sync is not supported");

            return response;
        }

        internal static byte[] DecryptVaultKey(R.Session session, string password)
        {
            return ExecCryptoCode(() =>
                Crypto.DecryptVaultKey(session.Keys.EncryptionParams.Decode64Loose(), password)
            );
        }

        internal static Account[] DecryptVault(R.EncryptedVault vault, byte[] vaultKey)
        {
            return ExecCryptoCode(() => {
                var idToPath = DecryptAccountFolderPaths(vault, vaultKey);
                var meta = vault.RecordMeta.ToDictionary(x => x.Id);
                return vault.Records
                    .Select(x => DecryptAccount(x, DecryptAccountKey(meta[x.Id], vaultKey), idToPath))
                    .ToArray();
            });
        }

        // This function simply executes another function and re-throws
        // any crypto exceptions as internal errors.
        internal static T ExecCryptoCode<T>(Func<T> action)
        {
            try
            {
                return action();
            }
            catch (CryptoException e)
            {
                // CryptoException is internal, it's TMI for the user.
                throw MakeCorruptedError(e);
            }
        }

        internal static Dictionary<string, string> DecryptAccountFolderPaths(R.EncryptedVault vault, byte[] vaultKey)
        {
            try
            {
                var folderIdToFolderPaths = DecryptFolders(vault.Folders, vaultKey);
                var accountIdToFolderPath = vault.RecordFolderRairs.ToDictionary(
                    x => x.RecordId,
                    x => x.FolderId.IsNullOrEmpty() ? "" : folderIdToFolderPaths[x.FolderId]);

                return accountIdToFolderPath;
            }
            catch (KeyNotFoundException e)
            {
                throw MakeCorruptedError(e);
            }
        }

        internal static Dictionary<string, string> DecryptFolders(R.Folder[] folders, byte[] vaultKey)
        {
            var idToName = folders.ToDictionary(x => x.Id, x => DecryptFolderName(x, vaultKey));
            var idToParent = folders.ToDictionary(x => x.Id, x => x.ParentId);
            var idToPath = folders.ToDictionary(x => x.Id, x => BuildFolderPath(x.Id, idToName, idToParent));

            return idToPath;
        }

        internal static string DecryptFolderName(R.Folder folder, byte[] vaultKey)
        {
            if (folder.KeyType != 1)
                throw new UnsupportedFeatureException($"Folder key type {folder.KeyType} is not supported");

            if (folder.Type != "user_folder")
                throw new UnsupportedFeatureException($"Folder type '{folder.Type}' is not supported");

            var key = Crypto.DecryptContainer(folder.Key.Decode64Loose(), vaultKey);
            var json = Crypto.DecryptContainer(folder.Data.Decode64Loose(), key).ToUtf8();
            var data = JsonConvert.DeserializeObject<R.FolderData>(json);

            return data.Name;
        }

        private static string BuildFolderPath(string id,
                                              Dictionary<string, string> idToName,
                                              Dictionary<string, string> idToParent)
        {
            try
            {
                var path = idToName[id];
                for (var parentId = idToParent[id]; !parentId.IsNullOrEmpty(); parentId = idToParent[parentId])
                    path = $"{idToName[parentId]}/{path}";

                return path;
            }
            catch (KeyNotFoundException e)
            {
                throw MakeCorruptedError(e);
            }
        }

        internal static byte[] DecryptAccountKey(R.RecordMeta meta, byte[] vaultKey)
        {
            if (meta.KeyType != 1)
                throw new UnsupportedFeatureException($"Account key type {meta.KeyType} is not supported");

            return Crypto.DecryptContainer(meta.Key.Decode64Loose(), vaultKey);
        }

        internal static Account DecryptAccount(R.Record record, byte[] accountKey, Dictionary<string, string> idToPath)
        {
            var json = Crypto.DecryptContainer(record.Data.Decode64Loose(), accountKey).ToUtf8();
            var data = JsonConvert.DeserializeObject<R.RecordData>(json);
            return new Account(id: record.Id,
                               name: data.Name,
                               username: data.Username,
                               password: data.Password,
                               url: data.Url,
                               note: data.Note,
                               folder: idToPath[record.Id]);
        }

        internal static long GetCurrentTimeInMs()
        {
            return DateTimeOffset.Now.ToUnixTimeMilliseconds();
        }

        internal static BaseException MakeError(R.Status response, string requestName)
        {
            switch (response.ResultCode)
            {
            case "Failed_to_find_user":
                return new BadCredentialsException("The username is invalid");
            case "auth_failed":
                return new BadCredentialsException("The password is invalid");
            default:
                return new InternalErrorException(string.Format("The '{0}' request failed: '{1}'",
                                                                requestName,
                                                                GetErrorMessage(response)));
            }
        }

        internal static InternalErrorException MakeCorruptedError(Exception original)
        {
            throw new InternalErrorException("The vault is invalid or corrupted", original);
        }

        internal static string GetErrorMessage(R.Status response)
        {
            if (!response.Message.IsNullOrEmpty())
                return response.Message;

            if (!response.ResultCode.IsNullOrEmpty())
                return response.ResultCode;

            return "unknown reason";
        }

        //
        // Data
        //

        private const string ClientVersion = "c13.0.0";
    }
}
