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
        public static Account[] OpenVault(string username,
                                          string password,
                                          Ui ui,
                                          ISecureStorage storage,
                                          IHttpClient http)
        {
            var jsonHttp = new JsonHttpClient(http, GetApiUrl(DefaultRegionHost));
            var kdfInfo = RequestKdfInfo(username, ref jsonHttp);

            var passwordHash = Crypto.HashPassword(password,
                                                   kdfInfo.Salt.Decode64Loose(),
                                                   kdfInfo.Iterations);
            var session = Login(username, passwordHash, ui, storage, jsonHttp);
            var encryptedVault = RequestVault(username, session.Token, jsonHttp);
            var vaultKey = DecryptVaultKey(session.Keys, password);
            var accounts = DecryptVault(encryptedVault, vaultKey);

            return accounts;
        }

        //
        // Internal
        //

        // This function has a side effect: it might change jsonHttp when there's a region redirect.
        internal static R.KdfInfo RequestKdfInfo(string username, ref JsonHttpClient jsonHttp)
        {
            var response = jsonHttp.Post<R.KdfInfo>("", SharedLoginParameters(username));

            // It's not supposed to succeed at this point. So success is a failure.
            if (response.Failed)
            {
                switch (response.ResultCode)
                {
                case "auth_failed":
                    return response; // It responds with failure and it's ok. Done.

                case "region_redirect": // Region redirect. Need to change the API URL and try again.
                    jsonHttp = new JsonHttpClient(jsonHttp.Http, GetApiUrl(response.RegionHost), jsonHttp.Headers);
                    return RequestKdfInfo(username, ref jsonHttp);
                }
            }

            throw MakeError(response, "KDF info");
        }

        internal struct Session
        {
            public readonly string Token;
            public readonly R.Keys Keys;

            public Session(string token, R.Keys keys)
            {
                Token = token;
                Keys = keys;
            }
        }

        internal static Session Login(string username,
                                      byte[] passwordHash,
                                      Ui ui,
                                      ISecureStorage storage,
                                      JsonHttpClient jsonHttp)
        {
            var parameters = SharedLoginParameters(username);
            parameters["auth_response"] = passwordHash.ToUrlSafeBase64NoPadding();

            // If have a "remember me" token stored from one of the previous sessions,
            // we need to send it along
            var rememberMeToken = storage.LoadString(RememberMeTokenKey);
            if (!rememberMeToken.IsNullOrEmpty())
            {
                parameters["2fa_token"] = rememberMeToken;
                parameters["2fa_type"] = "device_token";
            }

            var response = jsonHttp.Post<R.Login>("", parameters);
            if (response.Ok)
                return new Session(response.Token, response.Keys);

            // need_totp means MFA is required
            bool needMfa = response.ResultCode == "need_totp";

            // The token is expired or invalid
            if (response.ResultCode == "invalid_device_token")
            {
                storage.StoreString(RememberMeTokenKey, null);
                needMfa = true;
            }

            if (needMfa)
                return MfaLogin(response.Channel, parameters, ui, storage, jsonHttp);

            throw MakeError(response, "login");
        }

        internal static Session MfaLogin(string method,
                                         Dictionary<string, object> parameters,
                                         Ui ui,
                                         ISecureStorage storage,
                                         JsonHttpClient jsonHttp)
        {
            int attempt = 0;
            while (true)
            {
                try
                {
                    return MfaLoginAttempt(attempt++, method, parameters, ui, storage, jsonHttp);
                }
                catch (BadMultiFactorException) when (attempt < MaxMfaAttempts)
                {
                    // Ignore the exception
                }
            }
        }

        internal static Session MfaLoginAttempt(int attempt,
                                                string method,
                                                Dictionary<string, object> parameters,
                                                Ui ui,
                                                ISecureStorage storage,
                                                JsonHttpClient jsonHttp)
        {
            var passcode = Ui.Passcode.Cancel;
            switch (method)
            {
            case "two_factor_channel_google":
                passcode = ui.ProvideGoogleAuthPasscode(attempt);
                break;
            case "two_factor_channel_sms":
                passcode = ui.ProvideSmsPasscode(attempt);
                break;
            default:
                throw new UnsupportedFeatureException($"MFA method '{method}' is not supported");
            }

            if (passcode == Ui.Passcode.Cancel)
                throw new CanceledMultiFactorException("MFA canceled by the user");

            parameters["2fa_token"] = passcode.Code;
            parameters["2fa_type"] = "one_time";

            var response = jsonHttp.Post<R.Login>("", parameters);
            if (response.Ok)
            {
                storage.StoreString(RememberMeTokenKey,
                                    passcode.RememberMe ? response.DeviceToken : null);
                return new Session(response.Token, response.Keys);
            }

            throw MakeError(response, "MFA login");
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

        internal static byte[] DecryptVaultKey(R.Keys keys, string password)
        {
            return ExecCryptoCode(() =>
                Crypto.DecryptVaultKey(keys.EncryptionParams.Decode64Loose(), password)
            );
        }

        internal static Account[] DecryptVault(R.EncryptedVault vault, byte[] vaultKey)
        {
            return ExecCryptoCode(() => {
                var idToPath = DecryptAccountFolderPaths(vault, vaultKey);
                var meta = vault.RecordMeta.ToDictionary(k => k.Id);
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
            var folderIdToFolderPaths = vault.Folders == null
                ? new Dictionary<string, string>()
                : DecryptFolders(vault.Folders, vaultKey);

            try
            {
                return vault.RecordFolderRairs.ToDictionary(
                    k => k.RecordId,
                    v => v.FolderId.IsNullOrEmpty() ? "" : folderIdToFolderPaths[v.FolderId]);
            }
            catch (KeyNotFoundException e)
            {
                throw MakeCorruptedError(e);
            }
        }

        internal static Dictionary<string, string> DecryptFolders(R.Folder[] folders, byte[] vaultKey)
        {
            var idToName = folders.ToDictionary(k => k.Id, v => DecryptFolderName(v, vaultKey));
            var idToParent = folders.ToDictionary(k => k.Id, v => v.ParentId);
            var idToPath = folders.ToDictionary(k => k.Id, v => BuildFolderPath(v.Id, idToName, idToParent));

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
            case "invalid_totp":
                return new BadMultiFactorException("The second factor code is invalid");
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

        internal static string GetApiUrl(string regionHost = DefaultRegionHost)
        {
            return string.Format(ApiUrlFormat, regionHost);
        }

        //
        // Data
        //

        private const string DefaultRegionHost = "keepersecurity.com";
        private const string ApiUrlFormat = "https://{0}/api/v2/";
        private const string ClientVersion = "c13.0.0";
        private const string RememberMeTokenKey = "remember-me-token";
        private const int MaxMfaAttempts = 3;
    }
}
