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
        public static R.Vault OpenVault(string username, Ui ui, IRestTransport transport)
        {
            var newRest = new RestClient(transport,
                                         "https://api.dashlane.com/v1/authentication/",
                                         new Dl1RequestSigner(),
                                         defaultHeaders: new Dictionary<string, string>
                                         {
                                             // TODO: Factor out constants
                                             ["Dashlane-Client-Agent"] = "{\"platform\":\"server_standalone\",\"version\":\"6.2236.11\"}",
                                             ["User-Agent"] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36",
                                         });

            RequestEmailToken(username, newRest);
            var info = RegisterNewDevice(username, ui, newRest);
            var uki = $"{info.AccessKey}-{info.SecretKey}";
            return Client.Fetch(username, uki, new RestClient(transport, "https://ws1.dashlane.com/"));
        }

        internal static void RequestLogin(string username, RestClient rest)
        {
            var response = rest.PostJson<RW.Envelope<RW.VerificationMethods>>(
                "RequestLogin",
                new Dictionary<string, object>
                {
                    ["login"] = username,
                },
                headers: new Dictionary<string, string>
                {
                    ["Accept"] = "application/json",
                });
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
                        ["appVersion"] = "6.2236.11",
                        ["deviceName"] = "Chrome - Mac OS",
                        ["osCountry"] = "US",
                        ["osLanguage"] = "en-US",
                        ["platform"] = "server_standalone",
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
    }
}
