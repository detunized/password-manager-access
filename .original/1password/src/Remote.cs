// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using Newtonsoft.Json.Linq;

namespace OnePassword
{
    internal static class Remote
    {
        public static Session StartNewSession(ClientInfo clientInfo, IHttpClient http)
        {
            var response = Get(http, new[] {"auth", clientInfo.Username, clientInfo.Uuid, "-"});
            var status = response["status"].ToString();
            switch (status)
            {
            case "ok":
                return Session.Parse(response);
            default:
                // TODO: Use custom exception
                throw new InvalidOperationException(
                    string.Format(
                        "Failed to start a new session, unsupported response status '{0}'",
                        status));
            }
        }

        internal static JObject Get(IHttpClient http, string[] urlComponents)
        {
            // TODO: Handle network errors
            var response = http.Get(string.Join("/", urlComponents),
                                    new Dictionary<string, string>());
            return JObject.Parse(response);
        }
    }
}
