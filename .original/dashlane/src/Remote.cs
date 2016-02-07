// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Specialized;
using System.Net;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Dashlane
{
    public static class Remote
    {
        private const string LatestUrl = "https://www.dashlane.com/12/backup/latest";

        public static JObject Fetch(string username, string uki)
        {
            using (var webClient = new WebClient())
                return Fetch(username, uki, webClient);
        }

        public static JObject Fetch(string username, string uki, IWebClient webClient)
        {
            byte[] response;
            try
            {
                response = webClient.UploadValues(LatestUrl, new NameValueCollection {
                    {"login", username},
                    {"lock", "nolock"},
                    {"timestamp", "1"},
                    {"sharingTimestamp", "0"},
                    {"uki", uki},
                });
            }
            catch (WebException e)
            {
                throw new FetchException(
                    FetchException.FailureReason.NetworkError,
                    "Network error occurred",
                    e);
            }

            var parsed = ParseResponse(response);
            CheckForErrors(parsed);

            return parsed;
        }

        private static JObject ParseResponse(byte[] response)
        {
            try
            {
                return JObject.Parse(response.ToUtf8());
            }
            catch (JsonException e)
            {
                throw new FetchException(
                    FetchException.FailureReason.InvalidResponse,
                    "Invalid JSON in response",
                    e);
            }
        }

        private static void CheckForErrors(JObject response)
        {
            var error = response.SelectToken("error");
            if (error != null)
            {
                var message = error.GetString("message") ?? "Unknown error";
                throw new FetchException(
                    FetchException.FailureReason.UnknownError,
                    message);
            }

            if (response.GetString("objectType") == "message")
            {
                var message = response.GetString("content");
                if (message == null)
                    throw new FetchException(
                        FetchException.FailureReason.UnknownError,
                        "Unknown error");

                switch (message)
                {
                case "Incorrect authentification":
                    throw new FetchException(
                        FetchException.FailureReason.InvalidCredentials,
                        "Invalid username or password");
                default:
                    throw new FetchException(
                        FetchException.FailureReason.UnknownError,
                        message);
                }
            }
        }
    }
}
