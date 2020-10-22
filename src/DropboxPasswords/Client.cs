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
            var entries = rootFolder.Entries
                .Where(e => e.IsDownloadable && e.Tag == "file")
                .Select(e => DownloadFolderEntry(e.Path, features.Eligibility.RootPath, contentRest))
                .ToArray(); // This will force the actual download

            var keysets = entries.Where(e => e.Type == "keyset");
            var vault = entries.Where(e => e.Type == "password");

            throw new NotImplementedException();
        }

        //
        // Internal
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

            try
            {
                return JsonConvert.DeserializeObject<Response.EncryptedEntry>(response.Content);
            }
            catch (JsonException e)
            {
                throw MakeError($"Failed to parse JSON for the file at {path}");
            }
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

        internal static InternalErrorException MakeError(RestResponse response)
        {
            return MakeError($"POST request to {response.RequestUri} failed");
        }

        internal static InternalErrorException MakeError(string message)
        {
            return new InternalErrorException(message);
        }
    }
}
