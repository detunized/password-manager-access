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
            // See if we have access keys stored in the previous run
            // Server key is a server provided part of the password used in the vault decryption.
            // We do not store this. So in case OTP2 we need to request it every time.
            var accessKeys = LoadAccessKeys(storage);

            // If we have access keys we can try to fetch the vault
            if (accessKeys.IsValid)
            {
                try
                {
                    // TODO: Add an extra check no OTP2 is used. See "authentication/Get2FAStatusUnauthenticated" endpoint.
                    return (Fetch(username, accessKeys, transport), accessKeys.ServerKey);
                }
                catch (BadCredentialsException)
                {
                    // Erase the access keys and fall through to the full login
                    EraseAccessKeys(storage);
                }
            }

            // Either we failed to fetch the vault or we didn't have access keys in the first place.
            var result = RegisterNewDeviceWithMultipleAttempts(username, ui, MakeAppRestClient(transport));

            // If we have OTP2 we need to erase the access keys
            if (result.AccessKeys.IsOtp2)
                EraseAccessKeys(storage);
            else if (result.RememberMe)
                StoreAccessKeys(result.AccessKeys, storage);

            return (Fetch(username, result.AccessKeys, transport), result.AccessKeys.ServerKey);
        }

        //
        // Internal
        //

        internal record AccessKeys(string AccessKey, string SecretKey, string ServerKey)
        {
            public bool IsValid => !AccessKey.IsNullOrEmpty() && !SecretKey.IsNullOrEmpty();
            public bool IsOtp2 => !ServerKey.IsNullOrEmpty();
        }

        internal record RegisterResult(AccessKeys AccessKeys, bool RememberMe);

        internal static RegisterResult RegisterNewDeviceWithMultipleAttempts(string username, Ui ui, RestClient rest)
        {
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

                return new RegisterResult(new AccessKeys(info.AccessKey, info.SecretKey, info.ServerKey ?? ""), code.RememberMe);
            }
        }

        internal static R.VerificationMethod[] RequestDeviceRegistration(string username, RestClient rest)
        {
            return PostJson<R.VerificationMethods>(
                "authentication/GetAuthenticationMethodsForDevice",
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
            // TODO: We need to open a browser to trigger the email 2FA
            throw new UnsupportedFeatureException("Triggering email 2FA is not supported yet. Come back later.");
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
            throw new UnsupportedFeatureException($"None of the available MFA methods are supported: [{names}]");
        }

        // Returns auth ticket
        internal static string SubmitEmailToken(string username, string token, RestClient rest)
        {
            return PostJson<R.AuthTicket>(
                "authentication/PerformEmailTokenVerification",
                new Dictionary<string, object> { ["login"] = username, ["token"] = token },
                rest
            ).Ticket;
        }

        // Returns auth ticket
        internal static string SubmitOtpToken(string username, string token, RestClient rest)
        {
            return PostJson<R.AuthTicket>(
                "authentication/PerformTotpVerification",
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
                "authentication/CompleteDeviceRegistrationWithAuthTicket",
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

        internal static R.Vault Fetch(string username, AccessKeys accessKeys, IRestTransport transport) =>
            Fetch(MakeDeviceRestClient(transport, username, accessKeys));

        internal static R.Vault Fetch(RestClient rest)
        {
            var parameters = new Dictionary<string, object>
            {
                ["timestamp"] = 0,
                ["needsKeys"] = false,
                ["teamAdminGroups"] = false,
                ["transactions"] = Array.Empty<string>(),
            };

            return PostJson<R.Vault>("sync/GetLatestContent", parameters, rest);
        }

        //
        // Error handling
        //

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
                case "invalid_authentication":
                case "unknown_userdevice_key":
                    return new BadCredentialsException($"Invalid access codes: '{error.Message}'");
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
        // Rest clients
        //

        internal static RestClient MakeAppRestClient(IRestTransport transport) => MakeRestClient(new Dl1AppRequestSigner(), transport);

        internal static RestClient MakeDeviceRestClient(IRestTransport transport, string username, AccessKeys accessKeys) =>
            MakeRestClient(
                new Dl1DeviceRequestSigner
                {
                    Username = username,
                    DeviceAccessKey = accessKeys.AccessKey,
                    DeviceSecretKey = accessKeys.SecretKey,
                },
                transport
            );

        internal static RestClient MakeRestClient(IRequestSigner signer, IRestTransport transport) =>
            new(
                transport,
                AuthApiBaseUrl,
                signer,
                defaultHeaders: new Dictionary<string, string>(2) { ["Dashlane-Client-Agent"] = ClientAgent, ["User-Agent"] = UserAgent }
            );

        //
        // Storage
        //

        internal static AccessKeys LoadAccessKeys(ISecureStorage storage) =>
            // We don't store the server key
            new(storage.LoadString(DeviceAccessKeyKey), storage.LoadString(DeviceSecretKeyKey), "");

        internal static void StoreAccessKeys(AccessKeys accessKeys, ISecureStorage storage)
        {
            // We don't store the server key
            storage.StoreString(DeviceAccessKeyKey, accessKeys.AccessKey);
            storage.StoreString(DeviceSecretKeyKey, accessKeys.SecretKey);
        }

        internal static void EraseAccessKeys(ISecureStorage storage)
        {
            storage.StoreString(DeviceAccessKeyKey, "");
            storage.StoreString(DeviceSecretKeyKey, "");
        }

        //
        // Data
        //

        // Storage keys
        private const string DeviceAccessKeyKey = "device-access-key";
        private const string DeviceSecretKeyKey = "device-secret-key";

        private const string AuthApiBaseUrl = "https://api.dashlane.com/v1/";
        private const string UserAgent = "Dashlane CLI v6.2526.2";
        private const string AppVersion = "6.2526.2";
        private const string Platform = "server_cli";
        private const string ClientName = "hostname.local - darwin-arm64";
        private const int MaxMfaAttempts = 3;
        private const string ClientAgent =
            $$"""{"version":"{{AppVersion}}","platform":"{{Platform}}","osversion":"darwin-arm64","partner":"dashlane"}""";
    }
}
