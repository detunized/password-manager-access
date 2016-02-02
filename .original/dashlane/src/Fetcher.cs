// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Specialized;
using Newtonsoft.Json.Linq;

namespace Dashlane
{
    static class Fetcher
    {
        public const string LatestUrl = "https://www.dashlane.com/12/backup/latest";

        public static string Fetch(string username, string uki)
        {
            using (var webClient = new WebClient())
                return Fetch(username, uki, webClient);
        }

        public static string Fetch(string username, string uki, IWebClient webClient)
        {
            // TODO: Handle web exceptions!

            var response = webClient.UploadValues(LatestUrl, new NameValueCollection {
                {"login", username},
                {"lock", "nolock"},
                {"timestamp", "1"},
                {"sharingTimestamp", "0"},
                {"uki", uki},
            }).ToUtf8();

            CheckForErrorsAndThrow(response);

            return response;
        }

        // TODO: Use custom exceptions!
        private static void CheckForErrorsAndThrow(string response)
        {
            var parsed = JToken.Parse(response);

            var error = parsed.SelectToken("error");
            if (error != null)
            {
                var message = error.GetString("message") ?? "Unknown error";
                throw new InvalidOperationException(message);
            }

            if (parsed.GetString("objectType") == "message")
            {
                var message = parsed.GetString("content");
                if (message == null)
                    throw new InvalidOperationException("Unknown error");

                switch (message)
                {
                case "Incorrect authentification":
                    throw new InvalidOperationException("Invalid username or password");
                default:
                    throw new InvalidOperationException(message);
                }
            }
        }
    }
}
