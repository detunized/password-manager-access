// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Specialized;
using System.Net;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Dashlane
{
    public static class Remote
    {
        private const string LatestUrl = "https://www.dashlane.com/12/backup/latest";
        private const string TokenUrl = "https://www.dashlane.com/6/authentication/sendtoken";
        private const string RegisterUrl = "https://www.dashlane.com/6/authentication/registeruki";

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

        public static void RegisterUkiStep1(string username)
        {
            using (var webClient = new WebClient())
                RegisterUkiStep1(username, webClient);
        }

        public static void RegisterUkiStep1(string username, IWebClient webClient)
        {
            byte[] response;
            try
            {
                response = webClient.UploadValues(TokenUrl, new NameValueCollection {
                    {"login", username},
                    {"isOTPAware", "true"},
                });
            }
            catch (WebException e)
            {
                throw new RegisterException(
                    RegisterException.FailureReason.NetworkError,
                    "Network error occurred",
                    e);
            }

            if (response.ToUtf8() != "SUCCESS")
                throw new RegisterException(
                    RegisterException.FailureReason.InvalidResponse,
                    "Register UKI failed");
        }

        public static void RegisterUkiStep2(string username, string deviceName, string uki, string token)
        {
            using (var webClient = new WebClient())
                RegisterUkiStep2(username, deviceName, uki, token, webClient);
        }

        public static void RegisterUkiStep2(
            string username,
            string deviceName,
            string uki,
            string token,
            IWebClient webClient)
        {
            byte[] response;
            try
            {
                response = webClient.UploadValues(RegisterUrl, new NameValueCollection {
                    {"devicename", deviceName},
                    {"login", username},
                    {"platform", "webaccess"},
                    {"temporary", "0"},
                    {"token", token},
                    {"uki", uki},
                });
            }
            catch (WebException e)
            {
                throw new RegisterException(
                    RegisterException.FailureReason.NetworkError,
                    "Network error occurred",
                    e);
            }

            if (response.ToUtf8() != "SUCCESS")
                throw new RegisterException(
                    RegisterException.FailureReason.InvalidResponse,
                    "Register UKI failed");
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
