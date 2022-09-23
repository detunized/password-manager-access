using System.Collections.Generic;
using System.Linq;
using PasswordManagerAccess.Common;
using R = PasswordManagerAccess.Dashlane.ResponseWeb;

namespace PasswordManagerAccess.Dashlane
{
    // The new web protocol partial implementation.
    // The new web protocol doesn't seem to be fully implemented by Dashlane. They fall back
    // to ws1.dashlane.com calls all the time. Some features are not supported by the
    // web/extension clients. It's been put on ice for now.
    internal static class ClientWeb
    {
        public static void OpenVault(string username, Ui ui, IRestTransport transport)
        {
            var newRest = new RestClient(transport,
                                         "https://api.dashlane.com/v1/authentication/",
                                         new Dl1RequestSigner(),
                                         defaultHeaders: new Dictionary<string, string>
                                         {
                                             ["dashlane-client-agent"] =
                                                 "{\"platform\":\"server_leeloo\",\"version\":\"57.220.0.1495220\"}",
                                             ["User-Agent"] =
                                                 "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
                                         });

            RequestEmailToken(username, newRest);
            var info = RegisterNewDevice(username, ui, newRest);

            // TODO: Fetch the vault with this UKI
            var uki = $"{info.AccessKey}-{info.SecretKey}";
        }

        internal static void RequestEmailToken(string username, RestClient rest)
        {
            var response = rest.PostJson<R.Envelope<R.VerificationMethods>>(
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

        internal static R.DeviceInfo RegisterNewDevice(string username, Ui ui, RestClient rest)
        {
            var code = ui.ProvideEmailPasscode(0);
            if (code == Ui.Passcode.Cancel)
                throw new CanceledMultiFactorException("MFA canceled by the user");

            var ticket = SubmitEmailToken(username, code.Code, rest);
            return RegisterDevice(username, ticket, code.RememberMe, rest);
        }

        internal static string SubmitEmailToken(string username, string token, RestClient rest)
        {
            var response = rest.PostJson<R.Envelope<R.AuthTicket>>("PerformEmailTokenVerification",
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

        internal static R.DeviceInfo RegisterDevice(string username, string ticket, bool rememberMe, RestClient rest)
        {
            var response = rest.PostJson<R.Envelope<R.DeviceInfo>>(
                "CompleteDeviceRegistrationWithAuthTicket",
                new Dictionary<string, object>
                {
                    ["login"] = username,
                    ["authTicket"] = ticket,
                    ["device"] = new Dictionary<string, object>
                    {
                        ["appVersion"] = "57.220.0.1516771",
                        ["deviceName"] = "password-manager-access",
                        ["osCountry"] = "US",
                        ["osLanguage"] = "en",
                        ["platform"] = "server_leeloo",
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
    }
}
