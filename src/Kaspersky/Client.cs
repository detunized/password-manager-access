// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using Newtonsoft.Json;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Kaspersky
{
    internal static class Client
    {
        public static void OpenVault(string username, string password, IRestTransport transport)
        {
            var rest = new RestClient(transport);

            // 1. Request login context token
            var loginContext = RequestLoginContext(rest);
        }

        //
        // Internal
        //

        internal static string RequestLoginContext(RestClient rest)
        {
            var response = rest.PostJson<R.Start>(
                "https://hq.uis.kaspersky.com/v3/logon/start",
                new Dictionary<string, object> {["Realm"] = "https://center.kaspersky.com/"});

            if (response.IsSuccessful)
                return response.Data.Context;

            throw MakeError(response);
        }

        internal static BaseException MakeError(RestResponse<string> response)
        {
            // TODO: Make this more descriptive
            return new InternalErrorException($"Request to '{response.RequestUri}' failed");
        }

        // TODO: Move this out of here
        internal static class R
        {
            internal class Start
            {
                [JsonProperty("Status", Required = Required.Always)]
                public readonly string Status;

                [JsonProperty("LogonContext", Required = Required.Always)]
                public readonly string Context;
            }
        }
    }
}
