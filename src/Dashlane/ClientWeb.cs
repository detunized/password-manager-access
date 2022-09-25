using System;
using System.Collections.Generic;
using System.Linq;
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
                    uki = RegisterNewDevice(username, ui, transport);
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
        internal static string RegisterNewDevice(string username, Ui ui, IRestTransport transport)
        {
            var rest = new RestClient(transport,
                                      AuthApiBaseUrl,
                                      new Dl1RequestSigner(),
                                      defaultHeaders: new Dictionary<string, string>(2)
                                      {
                                          ["Dashlane-Client-Agent"] = ClientAgent,
                                          ["User-Agent"] = UserAgent,
                                      });

            RequestEmailToken(username, rest);
            var info = RegisterNewDevice(username, ui, rest);
            return $"{info.AccessKey}-{info.SecretKey}";
        }

        internal static void RequestEmailToken(string username, RestClient rest)
        {
            var response = rest.PostJson<RW.Envelope<RW.VerificationMethods>>(
                "RequestDeviceRegistration",
                new Dictionary<string, object>
                {
                    ["login"] = username,
                },
                headers: new Dictionary<string, string>
                {
                    ["Accept"] = "application/json",
                });

            if (!response.IsSuccessful)
                throw Client.MakeSpecializedError(response);

            if (response.Data.Data.Methods.Any(x => x.Name == "email_token"))
                return;

            throw new InternalErrorException("Unexpected response: no email MFA method found");
        }

        internal static RW.DeviceInfo RegisterNewDevice(string username, Ui ui, RestClient rest)
        {
            var code = ui.ProvideEmailPasscode(0);
            if (code == Ui.Passcode.Cancel)
                throw new CanceledMultiFactorException("MFA canceled by the user");

            var ticket = SubmitEmailToken(username, code.Code, rest);
            var deviceInfo = RegisterDevice(username, ticket, code.RememberMe, rest);
            // TODO: "Remember me" related
            //var pairingId = RequestPairing(rest);
            return deviceInfo;
        }

        internal static string SubmitEmailToken(string username, string token, RestClient rest)
        {
            var response = rest.PostJson<RW.Envelope<RW.AuthTicket>>("PerformEmailTokenVerification",
                                                                   new Dictionary<string, object>
                                                                   {
                                                                       ["login"] = username,
                                                                       ["token"] = token,
                                                                   },
                                                                   headers: new Dictionary<string, string>
                                                                   {
                                                                       ["Accept"] = "application/json",
                                                                   });

            if (!response.IsSuccessful)
                throw Client.MakeSpecializedError(response);

            return response.Data.Data.Ticket;
        }

        internal static RW.DeviceInfo RegisterDevice(string username, string ticket, bool rememberMe, RestClient rest)
        {
            var response = rest.PostJson<RW.Envelope<RW.DeviceInfo>>(
                "CompleteDeviceRegistrationWithAuthTicket",
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
                headers: new Dictionary<string, string>
                {
                    ["Accept"] = "application/json",
                });

            if (!response.IsSuccessful)
                throw Client.MakeSpecializedError(response);

            return response.Data.Data;
        }

        internal static string RequestPairing(RestClient rest)
        {
            var response = rest.PostJson<RW.Envelope<RW.PairingInfo>>(
                "CompleteDeviceRegistrationWithAuthTicket",
                RestClient.NoParameters,
                headers: new Dictionary<string, string>
                {
                    ["Accept"] = "application/json",
                });

            if (!response.IsSuccessful)
                throw Client.MakeSpecializedError(response);

            return response.Data.Data.PairingId;
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
        private static readonly string ClientAgent = $"{{\"platform\":\"{Platform}\",\"version\":\"{AppVersion}\"}}";
    }
}
