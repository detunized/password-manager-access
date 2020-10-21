// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using PasswordManagerAccess.Common;
using R = PasswordManagerAccess.DropboxPasswords.Response;

namespace PasswordManagerAccess.DropboxPasswords
{
    public static class Client
    {
        public static void OpenVault(string oauthToken)
        {
            using var transport = new RestTransport();
            var rest = new RestClient(transport,
                                      "https://api.dropboxapi.com/2",
                                      defaultHeaders: new Dictionary<string, string>
                                      {
                                          ["Authorization"] = $"Bearer {oauthToken}"
                                      });

            // 1. Get account info
            var accountInfo = Post<R.AccountInfo>("users/get_current_account", rest);
            if (accountInfo.Disabled)
                throw new InternalErrorException($"The account is disabled");

            // 2. Get features
            var features = Post<R.Features>("passwords/get_features_v2", rest);
            if (features.Eligibility.Tag != "enabled")
                throw new InternalErrorException("Dropbox Passwords is not enabled on this account");

            // 3. List the root folder
            // TODO: Very long folders are not supported. See "has_more" and "cursor".
            var rootFolder = Post<R.RootFolder>("files/list_folder",
                                                new Dictionary<string, object> {["path"] = ""},
                                                MakeRootPathHeaders(features.Eligibility.RootPath),
                                                rest);

            throw new NotImplementedException();
        }

        //
        // Internal
        //

        internal static Dictionary<string, string> MakeRootPathHeaders(string rootPath)
        {
            return new Dictionary<string, string>
            {
                ["Dropbox-API-Path-Root"] = $"{{\".tag\":\"namespace_id\",\"namespace_id\":\"{rootPath}\"}}"
            };
        }

        internal static T Post<T>(string endpoint, RestClient rest)
        {
            // It's important to pass `null` and not the `RestClient.NoParameters`. Some requests are rejected
            // by the the Dropbox servers when they have non-empty payload.
            return Post<T>(endpoint, null, RestClient.NoHeaders, rest);
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
                throw new InternalErrorException($"POST request to {response.RequestUri} failed");

            return response.Data;
        }
    }
}
