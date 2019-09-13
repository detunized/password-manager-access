// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Dashlane
{
    using R = Response;

    internal static class Remote
    {
        private const string LoginTypeUrl = "https://ws1.dashlane.com/7/authentication/exists";
        private const string LatestUrl = "https://ws1.dashlane.com/12/backup/latest";
        private const string TokenUrl = "https://ws1.dashlane.com/6/authentication/sendtoken";
        private const string RegisterUrl = "https://ws1.dashlane.com/6/authentication/registeruki";

        public enum LoginType
        {
            DoesntExist,
            Regular,
            GoogleAuth,
        }

        public static LoginType RequestLoginType(string username, IRestTransport transport)
        {
            return RequestLoginType(username, new RestClient(transport));
        }

        public static LoginType RequestLoginType(string username, RestClient rest)
        {
            var response = rest.PostForm<R.LoginType>(LoginTypeUrl, new Dictionary<string, object> {{"login", username}});
            if (response.IsSuccessful)
            {
                string type = response.Data.Exists;
                switch (type)
                {
                case "NO":
                    return LoginType.DoesntExist;
                case "YES":
                    return LoginType.Regular;
                case "YES_OTP_LOGIN":
                    return LoginType.GoogleAuth;
                }

                throw new UnsupportedFeatureException($"Login type '{type}' is not supported");
            }

            throw MakeSpecializedError(response);
        }

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

        public static void RegisterUkiStep1(string username, IRestTransport transport)
        {
            PerformRegisterUkiStep(transport, rest => rest.PostForm(TokenUrl, new Dictionary<string, object>
            {
                {"login", username},
                {"isOTPAware", "true"},
            }));
        }

        public static void RegisterUkiStep2(string username,
                                            string deviceName,
                                            string uki,
                                            string token,
                                            IRestTransport transport)
        {
            PerformRegisterUkiStep(transport, rest => rest.PostForm(RegisterUrl, new Dictionary<string, object>
            {
                {"devicename", deviceName},
                {"login", username},
                {"platform", "webaccess"},
                {"temporary", "0"},
                {"token", token},
                {"uki", uki},
            }));
        }

        private static void PerformRegisterUkiStep(IRestTransport transport, Func<RestClient, RestResponse> makeRequest)
        {
            var response = makeRequest((RestClient)new RestClient((IRestTransport)transport));

            if (response.IsSuccessful && response.Content == "SUCCESS")
                return;

            if (response.HasError)
                throw new NetworkErrorException("Network error occurred", response.Error);

            throw new InternalErrorException("Register UKI failed", response.Error);
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

        private static Common.BaseException MakeSpecializedError(RestResponse response)
        {
            Uri uri = response.RequestUri;

            if (response.IsHttpError)
                return new InternalErrorException(
                    $"HTTP request to {uri} failed with status {response.StatusCode}");

            if (response.IsNetworkError)
                return new NetworkErrorException(
                    $"A network error occurred during a request to {uri}", response.Error);

            if (response.Error is JsonException)
                return new InternalErrorException(
                    $"Failed to parse JSON response from {uri}", response.Error);

            return new InternalErrorException($"Unexpected response from {uri}", response.Error);
        }
    }
}
