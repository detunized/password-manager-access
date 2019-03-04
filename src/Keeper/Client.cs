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

            // 1. Get KDF info
            var kdfInfo = RequestKdfInfo(username, jsonHttp);

            // 2. Hash the password to prove identity
            var passwordHash = Crypto.HashPassword(password,
                                                   kdfInfo.Salt.Decode64Loose(),
                                                   kdfInfo.Iterations);

            // 3. Login
            var session = Login(username, passwordHash, jsonHttp);

            // 4. Get vault
            var encryptedVault = RequestVault(username, session.Token, jsonHttp);

            // 5. Decrypt vault key
            var vaultKey = Crypto.DecryptVaultKey(session.Keys.EncryptionParams.Decode64Loose(),
                                                  password);

            // 6. Parse and decrypt accounts
            var accounts = DecryptVault(encryptedVault, vaultKey);

            return accounts;
        }

        //
        // Internal
        //

        internal static R.KdfInfo RequestKdfInfo(string username, JsonHttpClient jsonHttp)
        {
            return jsonHttp.Post<R.KdfInfo>("", SharedLoginParameters(username));
        }

        internal static R.Session Login(string username, byte[] passwordHash, JsonHttpClient jsonHttp)
        {
            var parameters = SharedLoginParameters(username);
            parameters["auth_response"] = passwordHash.ToUrlSafeBase64NoPadding();

            var response = jsonHttp.Post<R.Session>("", parameters);
            if (response.Result != "success")
            {
                var error = response.Message.IsNullOrEmpty() ? response.ResultCode : response.Message;
                throw new InternalErrorException($"Login failed: '{error}'");
            }

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

            if (response.Result != "success")
                throw new InternalErrorException("Login failed, the server responded with error");

            if (!response.FullSync)
                throw new UnsupportedFeatureException("Partial sync is not supported");

            return response;
        }

        internal static Account[] DecryptVault(R.EncryptedVault vault, byte[] vaultKey)
        {
            var meta = vault.RecordMeta.ToDictionary(x => x.Id);
            return vault.Records
                .Select(x => DecryptAccount(x, DecryptAccountKey(meta[x.Id], vaultKey)))
                .ToArray();
        }

        internal static byte[] DecryptAccountKey(R.RecordMeta meta, byte[] vaultKey)
        {
            return Crypto.DecryptContainer(meta.Key.Decode64Loose(), vaultKey);
        }

        internal static Account DecryptAccount(R.Record record, byte[] accountKey)
        {
            var json = Crypto.DecryptContainer(record.Data.Decode64Loose(), accountKey).ToUtf8();
            var data = JsonConvert.DeserializeObject<R.RecordData>(json);
            return new Account(id: record.Id,
                               name: data.Name,
                               username: data.Username,
                               password: data.Password,
                               url: data.Url,
                               note: data.Note,
                               folder: "TODO");
        }

        internal static long GetCurrentTimeInMs()
        {
            return DateTimeOffset.Now.ToUnixTimeMilliseconds();
        }

        //
        // Data
        //

        private const string ClientVersion = "c13.0.0";
    }
}
