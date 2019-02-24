// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using Newtonsoft.Json;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Keeper
{
    internal static class Client
    {
        public static void OpenVault(string username, string password, IHttpClient http)
        {
            var jsonHttp = new JsonHttpClient(http, "https://keepersecurity.com/api/v2/");

            // 1. Get KDF info
            var kdfInfo = RequestKdfInfo(username, jsonHttp);

            // 2. Hash the password to prove identity
            var passwordHash = Crypto.HashPassword(password,
                                                   kdfInfo.Salt.Decode64Loose(),
                                                   kdfInfo.Iterations);
        }

        //
        // Internal
        //

        internal struct KdfInfo
        {
            [JsonProperty(PropertyName ="result")]
            public string Result;

            [JsonProperty(PropertyName = "result_code")]
            public string ResultCode;

            [JsonProperty(PropertyName = "message")]
            public string Message;

            [JsonProperty(PropertyName = "salt")]
            public string Salt;

            [JsonProperty(PropertyName = "iterations")]
            public int Iterations;
        }

        internal static KdfInfo RequestKdfInfo(string username, JsonHttpClient jsonHttp)
        {
            return jsonHttp.Post<KdfInfo>("", new Dictionary<string, object>
            {
                {"command", "login"},
                {"include", new []{"keys"}},
                {"version", 2},
                {"client_version", ClientVersion},
                {"username", username},
            });
        }

        //
        // Data
        //

        private const string ClientVersion = "c13.0.0";
    }
}
