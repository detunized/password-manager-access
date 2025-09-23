// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json;
using PasswordManagerAccess.Common;
using R = PasswordManagerAccess.Dashlane.Response;

namespace PasswordManagerAccess.Dashlane
{
    internal static class Client
    {
        public static (R.Vault Vault, string ServerKey) OpenVault(string username, Ui ui, ISecureStorage storage, IRestTransport transport)
        {
            // Dashlane requires a registered known to the server device ID (UKI) to access the vault. When there's no
            // UKI available we need to initiate a login sequence with a forced OTP.
            var uki = storage.LoadString(DeviceUkiKey);

            // Server key is a server provided part of the password used in the vault decryption.
            var serverKey = "";

            // Give 2 attempts max
            // 1. Possibly fail to fetch the vault with an expired UKI
            // 2. Try again with a new one
            for (var i = 0; i < 2; i++)
            {
                if (uki.IsNullOrEmpty())
                {
                    var registerResult = RegisterNewDeviceWithMultipleAttempts(username, ui, transport);

                    uki = registerResult.Uki;
                    serverKey = registerResult.ServerKey;

                    if (registerResult.RememberMe)
                        storage.StoreString(DeviceUkiKey, uki);

                    // We don't want to try twice with a newly issued UKI. Take one attempt away.
                    i++;
                }

                try
                {
                    return (Fetch(username, uki, transport), serverKey);
                }
                catch (BadCredentialsException)
                {
                    // In case of expired or invalid UKI we get a BadCredentialsException here
                    // Wipe the old UKI as it's no longer valid and try again
                    uki = "";
                    storage.StoreString(DeviceUkiKey, "");
                }
            }

            throw new InternalErrorException("Failed to fetch the vault");
        }

        //
        // Internal
        //

        internal readonly struct RegisterResult
        {
            public readonly string Uki;
            public readonly string ServerKey;
            public readonly bool RememberMe;

            public RegisterResult(string uki, string serverKey, bool rememberMe)
            {
                Uki = uki;
                ServerKey = serverKey;
                RememberMe = rememberMe;
            }
        }

        // Returns a valid UKI and "remember me"
        internal static RegisterResult RegisterNewDeviceWithMultipleAttempts(string username, Ui ui, IRestTransport transport)
        {
            var rest = new RestClient(
                transport,
                AuthApiBaseUrl,
                new Dl1RequestSigner(),
                defaultHeaders: new Dictionary<string, string>(2) { ["Dashlane-Client-Agent"] = ClientAgent, ["User-Agent"] = UserAgent }
            );

            var mfaMethods = RequestDeviceRegistration(username, rest);
            var mfaMethod = ChooseMfaMethod(mfaMethods);

            // When email 2FA is selected we need to tell the server to send the token to the user
            if (mfaMethod == MfaMethod.Email)
                TriggerEmailToken(username, rest);

            for (var attempt = 0; ; attempt++)
            {
                var code = mfaMethod switch
                {
                    MfaMethod.Email => ui.ProvideEmailPasscode(attempt),
                    MfaMethod.Otp => ui.ProvideGoogleAuthPasscode(attempt),
                    _ => throw new InternalErrorException("Logical error"),
                };

                if (code == Ui.Passcode.Cancel)
                    throw new CanceledMultiFactorException("MFA canceled by the user");

                if (code == Ui.Passcode.Resend)
                {
                    if (mfaMethod == MfaMethod.Email)
                    {
                        TriggerEmailToken(username, rest);
                        --attempt; // There was no attempt yet, we're just resending the token
                        continue;
                    }

                    throw new InternalErrorException("Return value Resend is invalid in this context");
                }

                // Both the email token and the GA OTP are 6 digits long. When we have something else the server
                // returns a "malformed request" error. It's hard to distinguish a legitimately malformed request
                // and a wrong code. So we make sure it's always 6 digits before we send it to the server.
                switch (mfaMethod)
                {
                    case MfaMethod.Email:
                    case MfaMethod.Otp:
                        if (!(code.Code.Length == 6 && code.Code.All(char.IsDigit)))
                        {
                            --attempt; // There was no attempt yet, we're re-requesting the code from the user
                            continue;
                        }
                        break;

                    // Future proofing
                    default:
                        throw new InternalErrorException("Logical error");
                }

                string ticket;
                try
                {
                    ticket = mfaMethod switch
                    {
                        MfaMethod.Email => SubmitEmailToken(username, code.Code, rest),
                        MfaMethod.Otp => SubmitOtpToken(username, code.Code, rest),
                        _ => throw new InternalErrorException("Logical error"),
                    };
                }
                catch (BadMultiFactorException) when (attempt < MaxMfaAttempts - 1)
                {
                    // Do nothing, try again
                    continue;
                }

                var info = RegisterDevice(username, ticket, code.RememberMe, rest);

                // TODO: Remove this
                var r = PostJson<R.MfaStatus>("Get2FAStatusUnauthenticated", new Dictionary<string, object> { ["login"] = username }, rest);

                return new RegisterResult($"{info.AccessKey}-{info.SecretKey}", info.ServerKey ?? "", code.RememberMe);
            }
        }

        internal static R.VerificationMethod[] RequestDeviceRegistration(string username, RestClient rest)
        {
            return PostJson<R.VerificationMethods>(
                "GetAuthenticationMethodsForDevice",
                new Dictionary<string, object>
                {
                    ["login"] = username,
                    ["methods"] = new[] { "email_token", "totp", "duo_push", "dashlane_authenticator" },
                },
                rest
            ).Methods;
        }

        internal static void TriggerEmailToken(string username, RestClient rest)
        {
            PostJson<R.Blank>("RequestEmailTokenVerification", new Dictionary<string, object> { ["login"] = username }, rest);
        }

        private enum MfaMethod
        {
            Email,
            Otp,
        }

        private static MfaMethod ChooseMfaMethod(R.VerificationMethod[] mfaMethods)
        {
            if (mfaMethods.Length == 0)
                throw new InternalErrorException("No MFA methods are provided by the server");

            if (mfaMethods.Any(x => x.Name == "totp"))
                return MfaMethod.Otp;

            if (mfaMethods.Any(x => x.Name == "email_token"))
                return MfaMethod.Email;

            var names = mfaMethods.Select(x => x.Name).JoinToString(", ");
            throw new UnsupportedFeatureException($"None of the [{names}] MFA methods are supported");
        }

        internal static string SubmitEmailToken(string username, string token, RestClient rest)
        {
            return PostJson<R.AuthTicket>(
                "PerformEmailTokenVerification",
                new Dictionary<string, object> { ["login"] = username, ["token"] = token },
                rest
            ).Ticket;
        }

        internal static string SubmitOtpToken(string username, string token, RestClient rest)
        {
            return PostJson<R.AuthTicket>(
                "PerformTotpVerification",
                new Dictionary<string, object>
                {
                    ["login"] = username,
                    ["otp"] = token,
                    ["activationFlow"] = false,
                },
                rest
            ).Ticket;
        }

        internal static R.DeviceInfo RegisterDevice(string username, string ticket, bool rememberMe, RestClient rest)
        {
            return PostJson<R.DeviceInfo>(
                "CompleteDeviceRegistrationWithAuthTicket",
                new Dictionary<string, object>
                {
                    ["device"] = new Dictionary<string, object>
                    {
                        ["deviceName"] = ClientName,
                        ["appVersion"] = AppVersion,
                        ["platform"] = Platform,
                        ["osCountry"] = "en_US",
                        ["osLanguage"] = "en_US",
                        ["temporary"] = !rememberMe,
                    },
                    ["login"] = username,
                    ["authTicket"] = ticket,
                },
                rest
            );
        }

        internal static T PostJson<T>(string endpoint, Dictionary<string, object> parameters, RestClient rest)
        {
            var response = rest.PostJson<R.Envelope<T>>(
                endpoint,
                parameters,
                headers: new Dictionary<string, string> { ["Accept"] = "application/json" }
            );

            if (response.IsSuccessful)
                return response.Data.Data;

            throw MakeSpecializedError(response, TryParseAuthError);
        }

        internal static R.Vault Fetch(string username, string deviceId, IRestTransport transport)
        {
            // Reuse the other RestClient
            var rest = new RestClient(
                transport,
                "https://api.dashlane.com/",
                new Dl1RequestSigner { Username = username, Uki = deviceId },
                defaultHeaders: new Dictionary<string, string> { ["Dashlane-Client-Agent"] = ClientAgent, ["User-Agent"] = UserAgent }
            );
            var parameters = new Dictionary<string, object>
            {
                ["timestamp"] = 0,
                ["needsKeys"] = false,
                ["teamAdminGroups"] = false,
                ["transactions"] = Array.Empty<string>(),
            };

            var response = rest.PostJson<R.Vault>("v1/sync/GetLatestContent", parameters);
            if (response.IsSuccessful)
                return response.Data;

            throw MakeSpecializedError(response, TryParseFetchError);
        }

        internal static BaseException MakeSpecializedError(RestResponse<string> response, Func<RestResponse<string>, BaseException> parseError)
        {
            var uri = response.RequestUri;

            if (response.IsNetworkError)
                return new NetworkErrorException($"A network error occurred during a request to {uri}", response.Error);

            // First try to parse the error JSON. It has a different schema.
            var error = parseError(response);
            if (error != null)
                return error;

            // The original JSON didn't parse either. This is usually due to changed format.
            if (response.Error is JsonException)
                return new InternalErrorException($"Failed to parse JSON response from {uri} (HTTP status: ${response.StatusCode})", response.Error);

            return new InternalErrorException($"Unexpected response from {uri} (HTTP status: ${response.StatusCode})", response.Error);
        }

        internal static BaseException TryParseAuthError(RestResponse<string> response)
        {
            var uri = response.RequestUri;
            R.ErrorEnvelope errorResponse;
            try
            {
                errorResponse = JsonConvert.DeserializeObject<R.ErrorEnvelope>(response.Content);
            }
            catch (JsonException e)
            {
                return new InternalErrorException($"Invalid JSON in response from '{uri}'", e);
            }

            if (errorResponse.Errors.Length == 0)
                return null;

            var error = errorResponse.Errors[0];
            switch (error.Code)
            {
                case "user_not_found":
                    return new BadCredentialsException($"Invalid username: '{error.Message}'");
                case "verification_failed":
                    return new BadMultiFactorException($"MFA failed: '{error.Message}'");
                default:
                    return new InternalErrorException($"Request failed with error: '{error.Message}'");
            }
        }

        internal static BaseException TryParseFetchError(RestResponse<string> response)
        {
            var uri = response.RequestUri;
            R.FetchError error;
            try
            {
                error = JsonConvert.DeserializeObject<R.FetchError>(response.Content);
            }
            catch (JsonException e)
            {
                return new InternalErrorException($"Invalid JSON in response from '{uri}'", e);
            }

            // "authentification" misspelled on the Dashlane side
            if (error.Type == "message" && error.Content == "Incorrect authentification")
                return new BadCredentialsException("Invalid credentials");

            return new InternalErrorException($"Request failed with error: '{error.Content}'");
        }

        //
        // Data
        //

        private const string AuthApiBaseUrl = "https://api.dashlane.com/v1/authentication/";
        private const string UserAgent = "Dashlane CLI v6.2526.2";
        private const string DeviceUkiKey = "device-uki";
        private const string AppVersion = "6.2526.2";
        private const string Platform = "server_cli";
        private const string ClientName = "hostname.local - darwin-arm64";
        private const int MaxMfaAttempts = 3;
        private static readonly string ClientAgent =
            $$"""{"version":"{{AppVersion}}","platform":"{{Platform}}","osversion":"darwin-arm64","partner":"dashlane"}""";
    }
}
