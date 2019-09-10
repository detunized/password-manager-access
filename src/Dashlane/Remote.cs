// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Collections.Specialized;
using System.Net;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Dashlane
{
    internal static class Remote
    {
        private const string LatestUrl = "https://ws1.dashlane.com/12/backup/latest";
        private const string TokenUrl = "https://ws1.dashlane.com/6/authentication/sendtoken";
        private const string RegisterUrl = "https://ws1.dashlane.com/6/authentication/registeruki";

        public static JObject Fetch(string username, string uki, IRestTransport transport)
        {
            var rest = new RestClient(transport);

            var response = rest.PostForm(LatestUrl, new Dictionary<string, object>
            {
                {"login", username},
                {"lock", "nolock"},
                {"timestamp", "1"},
                {"sharingTimestamp", "0"},
                {"uki", uki},
            });

            if (response.IsSuccessful)
            {
                var parsed = ParseResponse(response.Content);
                CheckForErrors(parsed);

                return parsed;
            }

            throw new NetworkErrorException("Network error occurred", response.Error);
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

        private static JObject ParseResponse(string response)
        {
            try
            {
                return JObject.Parse(response);
            }
            catch (JsonException e)
            {
                throw new InternalErrorException("Invalid JSON in response", e);
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
