using System;
using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json;
using PasswordManagerAccess.Common;

// TODO: Merge R and RW
using R = PasswordManagerAccess.Dashlane.Response;
using RW = PasswordManagerAccess.Dashlane.ResponseWeb;

namespace PasswordManagerAccess.Dashlane
{
    // The new web protocol partial implementation.
    // The new web protocol doesn't seem to be fully implemented by Dashlane. They fall back
    // to ws1.dashlane.com calls all the time. Some features are not supported by the
    // web/extension clients. It's been put on ice for now.
    internal static class ClientWeb
    {
        public static R.Vault OpenVault(string username, Ui ui, ISecureStorage storage, IRestTransport transport)
        {
            // Dashlane requires a registered known to the server device ID (UKI) to access the vault. When there's no
            // UKI available we need to initiate a login sequence with a forced OTP.
            var uki = storage.LoadString(DeviceUkiKey);

            // Give 2 attempts max
            // 1. Possibly fail to fetch the vault with an expired UKI
            // 2. Try again with a new one
            for (var i = 0; i < 2; i++)
            {
                if (uki.IsNullOrEmpty())
                {
                    uki = RegisterNewDeviceWithMultipleAttempts(username, ui, transport);
                    storage.StoreString(DeviceUkiKey, uki);

                    // We don't want to try twice with a newly issued UKI. Take one attempt away.
                    i++;
                }

                try
                {
                    return Client.Fetch(username, uki, transport);
                }
                catch (BadMultiFactorException)
                {
                    // In case of expired or invalid UKI we get a BadMultiFactorException here
                    // Wipe the old UKI as it's no longer valid and try again
                    uki = "";
                    storage.StoreString(DeviceUkiKey, "");
                }
            }

            throw new InternalErrorException("Failed to fetch the vault");
        }

        // Returns a valid UKI
        internal static string RegisterNewDeviceWithMultipleAttempts(string username, Ui ui, IRestTransport transport)
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

                try
                {
                    var ticket = mfaMethod switch
                    {
                        MfaMethod.Email => SubmitEmailToken(username, code.Code, rest),
                        MfaMethod.Otp => SubmitOtpToken(username, code.Code, rest),
                        _ => throw new InternalErrorException("Logical error"),
                    };

                    var info = RegisterDevice(username, ticket, code.RememberMe, rest);
                    return $"{info.AccessKey}-{info.SecretKey}";
                }
                catch (BadMultiFactorException) when (attempt < MaxMfaAttempts - 1)
                {
                    // Do nothing, try again
                }
            }
        }

        internal static RW.VerificationMethod[] RequestDeviceRegistration(string username, RestClient rest)
        {
            return PostJson<RW.VerificationMethods>("RequestDeviceRegistration",
                                                    new Dictionary<string, object>
                                                    {
                                                        ["login"] = username,
                                                    },
                                                    rest).Methods;
        }

        private enum MfaMethod
        {
            Email,
            Otp
        }

        private static MfaMethod ChooseMfaMethod(RW.VerificationMethod[] mfaMethods)
        {
            if (mfaMethods.Length == 0)
                throw new InternalErrorException("No MFA methods are provided by the server");

            if (mfaMethods.Any(x => x.Name == "totp"))
                return MfaMethod.Otp;

            if (mfaMethods.Any(x => x.Name == "email"))
                return MfaMethod.Email;


            var names = mfaMethods.Select(x => x.Name).JoinToString(", ");
            throw new UnsupportedFeatureException($"None of the [{names}] MFA methods are supported");
        }

        internal static string SubmitEmailToken(string username, string token, RestClient rest)
        {
            return PostJson<RW.AuthTicket>("PerformEmailTokenVerification",
                                           new Dictionary<string, object>
                                           {
                                               ["login"] = username,
                                               ["token"] = token,
                                           },
                                           rest).Ticket;
        }

        internal static string SubmitOtpToken(string username, string token, RestClient rest)
        {
            return PostJson<RW.AuthTicket>("PerformTotpVerification",
                                           new Dictionary<string, object>
                                           {
                                               ["login"] = username,
                                               ["otp"] = token,
                                           },
                                           rest).Ticket;
        }

        internal static RW.DeviceInfo RegisterDevice(string username, string ticket, bool rememberMe, RestClient rest)
        {
            return PostJson<RW.DeviceInfo>("CompleteDeviceRegistrationWithAuthTicket",
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
            var response = rest.PostJson<RW.Envelope<T>>(
                endpoint,
                parameters,
                headers: new Dictionary<string, string>
                {
                    ["Accept"] = "application/json",
                });

            if (response.IsSuccessful)
                return response.Data.Data;

            throw MakeSpecializedError(response);
        }

        internal static BaseException MakeSpecializedError(RestResponse<string> response)
        {
            var uri = response.RequestUri;

            if (response.IsNetworkError)
                return new NetworkErrorException($"A network error occurred during a request to {uri}", response.Error);

            // The request was successful but we failed to parse. This is usually due to changed format.
            if (response.IsHttpOk && response.Error is JsonException)
                return new InternalErrorException($"Failed to parse JSON response from {uri}", response.Error);

            // Otherwise we need to check for the returned error. This is also a JSON parsing error because the schema
            // for error and for regular responses are different.
            return TryParseReturnedError(response) ??
                   new InternalErrorException($"Unexpected response from {uri}", response.Error);
        }

        internal static BaseException TryParseReturnedError(RestResponse<string> response)
        {
            var uri = response.RequestUri;
            RW.ErrorEnvelope errorResponse;
            try
            {
                errorResponse = JsonConvert.DeserializeObject<RW.ErrorEnvelope>(response.Content);
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


        //
        // Data
        //

        private const string AuthApiBaseUrl = "https://api.dashlane.com/v1/authentication/";
        private const string UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36";
        private const string DeviceUkiKey = "device-uki";
        private const string AppVersion = "6.2236.11";
        private const string Platform = "server_standalone";
        private const string ClientName = "Chrome - Mac OS (PMA)";
        private const int MaxMfaAttempts = 3;
        private static readonly string ClientAgent = $"{{\"platform\":\"{Platform}\",\"version\":\"{AppVersion}\"}}";
    }
}
