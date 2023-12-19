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
        public static (R.Vault Vault, string ServerKey) OpenVault(string username, 
                                                                  Ui ui, 
                                                                  ISecureStorage storage, 
                                                                  IRestTransport transport)
        {
            // Dashlane requires a registered known to the server device ID (UKI) to access the vault. When there's no
            // UKI available we need to initiate a login sequence with a forced OTP.
            var uki = storage.LoadString(DeviceUkiKey);
            
            // Server key is a server provided part of the password used in the vault decryptioin.
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
        internal static RegisterResult RegisterNewDeviceWithMultipleAttempts(string username,
                                                                             Ui ui,
                                                                             IRestTransport transport)
        {
            var rest = new RestClient(transport,
                                      AuthApiBaseUrl,
                                      new Dl1RequestSigner(),
                                      defaultHeaders: new Dictionary<string, string>(2)
                                      {
                                          ["Dashlane-Client-Agent"] = ClientAgent,
                                          ["User-Agent"] = UserAgent,
                                      });

            var mfaMethods = RequestDeviceRegistration(username, rest);
            var mfaMethod = ChooseMfaMethod(mfaMethods);

            for (var attempt = 0;; attempt++)
            {
                var code = mfaMethod switch
                {
                    MfaMethod.Email => ui.ProvideEmailPasscode(attempt),
                    MfaMethod.Otp => ui.ProvideGoogleAuthPasscode(attempt),
                    _ => throw new InternalErrorException("Logical error"),
                };

                if (code == Ui.Passcode.Cancel)
                    throw new CanceledMultiFactorException("MFA canceled by the user");

                try
                {
                    var ticket = mfaMethod switch
                    {
                        MfaMethod.Email => SubmitEmailToken(username, code.Code, rest),
                        MfaMethod.Otp => SubmitOtpToken(username, code.Code, rest),
                        _ => throw new InternalErrorException("Logical error"),
                    };

                    var info = RegisterDevice(username, ticket, code.RememberMe, rest);
                    return new RegisterResult($"{info.AccessKey}-{info.SecretKey}",
                                              info.ServerKey ?? "",
                                              code.RememberMe);
                }
                catch (BadMultiFactorException) when (attempt < MaxMfaAttempts - 1)
                {
                    // Do nothing, try again
                }
            }
        }

        internal static R.VerificationMethod[] RequestDeviceRegistration(string username, RestClient rest)
        {
            return PostJson<R.VerificationMethods>("GetAuthenticationMethodsForDevice",
                                                   new Dictionary<string, object>
                                                   {
                                                       ["login"] = username,
                                                       ["methods"] = new[]
                                                       {
                                                           "email_token",
                                                           "totp",
                                                           "duo_push",
                                                           "dashlane_authenticator",
                                                           "u2f",
                                                       },
                                                   },
                                                   rest).Methods;
        }

        private enum MfaMethod
        {
            Email,
            Otp
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
            return PostJson<R.AuthTicket>("PerformEmailTokenVerification",
                                          new Dictionary<string, object>
                                          {
                                              ["login"] = username,
                                              ["token"] = token,
                                          },
                                          rest).Ticket;
        }

        internal static string SubmitOtpToken(string username, string token, RestClient rest)
        {
            return PostJson<R.AuthTicket>("PerformTotpVerification",
                                          new Dictionary<string, object>
                                          {
                                              ["login"] = username,
                                              ["otp"] = token,
                                          },
                                          rest).Ticket;
        }

        internal static R.DeviceInfo RegisterDevice(string username, string ticket, bool rememberMe, RestClient rest)
        {
            return PostJson<R.DeviceInfo>("CompleteDeviceRegistrationWithAuthTicket",
                                          new Dictionary<string, object>
                                          {
                                              ["login"] = username,
                                              ["authTicket"] = ticket,
                                              ["device"] = new Dictionary<string, object>
                                              {
                                                  ["appVersion"] = AppVersion,
                                                  ["deviceName"] = ClientName,
                                                  ["osCountry"] = "US",
                                                  ["osLanguage"] = "en-US",
                                                  ["platform"] = Platform,
                                                  ["temporary"] = !rememberMe,
                                              },
                                          },
                                          rest);
        }

        internal static T PostJson<T>(string endpoint, Dictionary<string, object> parameters, RestClient rest)
        {
            var response = rest.PostJson<R.Envelope<T>>(endpoint,
                                                        parameters,
                                                        headers: new Dictionary<string, string>
                                                        {
                                                            ["Accept"] = "application/json",
                                                        });

            if (response.IsSuccessful)
                return response.Data.Data;

            throw MakeSpecializedError(response, TryParseAuthError);
        }

        internal static R.Vault Fetch(string username, string deviceId, IRestTransport transport)
        {
            var rest = new RestClient(transport, FetchBaseApiUrl);
            var parameters = new Dictionary<string, object>
            {
                ["login"] = username,
                ["lock"] = "nolock",
                ["timestamp"] = "0",
                ["sharingTimestamp"] = "0",
                ["uki"] = deviceId,
            };

            var response = rest.PostForm<R.Vault>("12/backup/latest", parameters);
            if (response.IsSuccessful)
                return response.Data;

            throw MakeSpecializedError(response, TryParseFetchError);
        }

        internal static BaseException MakeSpecializedError(RestResponse<string> response,
                                                           Func<RestResponse<string>, BaseException> parseError)
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
                return new InternalErrorException(
                    $"Failed to parse JSON response from {uri} (HTTP status: ${response.StatusCode})",
                    response.Error);

            return new InternalErrorException($"Unexpected response from {uri} (HTTP status: ${response.StatusCode})",
                                              response.Error);
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
        private const string FetchBaseApiUrl = "https://ws1.dashlane.com/";
        private const string UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36";
        private const string DeviceUkiKey = "device-uki";
        private const string AppVersion = "6.2350-prod-webapp-60cde8db";
        private const string Platform = "server_leeloo";
        private const string ClientName = "Chrome - Mac OS (PMA)";
        private const int MaxMfaAttempts = 3;
        private static readonly string ClientAgent = $"{{\"platform\":\"{Platform}\",\"version\":\"{AppVersion}\",\"osversion\":\"OS_X_10_15_7\",\"language\":\"en\"}}";
    }
}
