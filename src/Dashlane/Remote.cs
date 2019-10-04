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
        // TODO: Don't return JObject
        public static JObject OpenVault(string username, string deviceId, Ui ui, IRestTransport transport)
        {
            // TODO: Use base url
            var rest = new RestClient(transport);

            var loginType = RequestLoginType(username, rest);
            if (loginType == LoginType.DoesntExist)
                throw new BadCredentialsException("Invalid username");

            if (!IsDeviceRegistered(username, deviceId, rest))
                RegisterNewDevice(username, deviceId, ui, rest);

            Ui.Passcode passcode = loginType == LoginType.GoogleAuth
                ? ui.ProvideGoogleAuthPasscode(0)
                : new Ui.Passcode("", false);

            if (passcode == Ui.Passcode.Cancel)
                throw new CanceledMultiFactorException("MFA canceled by the user");

            return Fetch(username, deviceId, passcode.Code ?? "", rest);
        }

        //
        // Internal
        //

        internal enum LoginType
        {
            DoesntExist,
            Regular,
            GoogleAuth,
        }

        internal static LoginType RequestLoginType(string username, RestClient rest)
        {
            var response = rest.PostForm<R.LoginType>(LoginTypeUrl, new Dictionary<string, object> { { "login", username } });
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
                case "YES_OTP_NEWDEVICE":
                    return LoginType.GoogleAuth;
                }

                throw new UnsupportedFeatureException($"Login type '{type}' is not supported");
            }

            throw MakeSpecializedError(response);
        }

        internal static bool IsDeviceRegistered(string username, string deviceId, RestClient rest)
        {
            var parameters = new Dictionary<string, object>
            {
                {"login", username},
                {"uki", deviceId},
            };

            var response = rest.PostForm<R.Status>(VerifyDeviceIdUrl, parameters);
            if (response.IsSuccessful)
                return response.Data.Code == 200 && response.Data.Message == "OK";

            throw MakeSpecializedError(response);
        }

        internal static void RegisterNewDevice(string username, string deviceId, Ui ui, RestClient rest)
        {
            var token = RequestToken(username, ui, rest);
            RegisterDeviceWithToken(username, "TODO: device name", deviceId, token, rest);
        }

        internal static string RequestToken(string username, Ui ui, RestClient rest)
        {
            while (true)
            {
                TriggerEmailWithToken(username, rest);

                var token = ui.ProvideEmailToken();
                if (token == Ui.EmailToken.Cancel)
                    throw new InternalErrorException("Canceled by user"); // TODO: Add new exception type
                else if (token == Ui.EmailToken.Resend)
                    continue;

                return token.Token;
            }
        }

        internal static void TriggerEmailWithToken(string username, RestClient rest)
        {
            var parameters = new Dictionary<string, object>
            {
                {"login", username},
                {"isOTPAware", "true"},
            };

            PerformRegisterDeviceStep(TokenUrl, parameters, rest);
        }

        internal static void RegisterDeviceWithToken(string username,
                                                     string deviceName,
                                                     string deviceId,
                                                     string token,
                                                     RestClient rest)
        {
            var parameters = new Dictionary<string, object>
            {
                {"devicename", deviceName},
                {"login", username},
                {"platform", "webaccess"},
                {"temporary", "0"},
                {"token", token},
                {"uki", deviceId},
            };

            PerformRegisterDeviceStep(RegisterUrl, parameters, rest);
        }

        internal static JObject Fetch(string username, string deviceId, string otp, RestClient rest)
        {
            var parameters = new Dictionary<string, object>
            {
                {"login", username},
                {"lock", "nolock"},
                {"timestamp", "0"},
                {"sharingTimestamp", "0"},
            };

            // The device ID should only be sent when no OTP is used. It fails otherwise!
            if (otp.IsNullOrEmpty())
                parameters["uki"] = deviceId;
            else
                parameters["otp"] = otp;

            var response = rest.PostForm(LatestUrl, parameters);
            if (response.IsSuccessful)
            {
                var parsed = ParseResponse(response.Content);
                CheckForErrors(parsed);

                return parsed;
            }

            throw new NetworkErrorException("Network error occurred", response.Error);
        }

        //
        // Private
        //

        private static void PerformRegisterDeviceStep(string url, Dictionary<string, object> parameters, RestClient rest)
        {
            var response = rest.PostForm(url, parameters);
            if (response.IsSuccessful && response.Content == "SUCCESS")
                return;

            throw MakeSpecializedError(response);
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
                throw new InternalErrorException($"Request failed with error: '{message}'");
            }

            if (response.GetString("objectType") == "message")
            {
                var message = response.GetString("content") ?? "Unknown error";
                switch (message)
                {
                case "Incorrect authentification": // Important: it's misspelled in the original code
                    throw new BadCredentialsException("Invalid username or password");
                default:
                    throw new InternalErrorException($"Request failed with error: '{message}'");
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

        //
        // Data
        //

        private const string LoginTypeUrl = "https://ws1.dashlane.com/7/authentication/exists";
        private const string VerifyDeviceIdUrl = "https://ws1.dashlane.com/1/features/getForUser";
        private const string LatestUrl = "https://ws1.dashlane.com/12/backup/latest";
        private const string TokenUrl = "https://ws1.dashlane.com/6/authentication/sendtoken";
        private const string RegisterUrl = "https://ws1.dashlane.com/6/authentication/registeruki";
    }
}
