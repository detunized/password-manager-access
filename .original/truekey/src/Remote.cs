// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace TrueKey
{
    internal static class Remote
    {
        public class DeviceInfo
        {
            public readonly string Token;
            public readonly string Id;

            public DeviceInfo(string token, string id)
            {
                Token = token;
                Id = id;
            }
        }

        // This is the first step in authentication process for a new device.
        // This requests the client token with is used in OCRA (RFC 6287) exchange
        // later on. There's also a server assigned id for the new device.
        //
        // `deviceName` is the name of the device registered with the True Key service.
        // For example 'Chrome' or 'Nexus 5'.
        public static DeviceInfo RegisetNewDevice(string deviceName, IHttpClient http)
        {
            return Post(http,
                        "https://truekeyapi.intelsecurity.com/sp/pabe/v2/so",
                        new Dictionary<string, object>
                        {
                            {"clientUDID", "truekey-sharp"},
                            {"deviceName", deviceName},
                            {"devicePlatformID", 7},
                            {"deviceType", 5},
                            {"oSName", "Unknown"},
                            {"oathTokenType", 1},
                        },
                        response => new DeviceInfo(response.StringAt("clientToken"),
                                                   response.StringAt("tkDeviceId")));
        }

        public class ClientInfo
        {
            public readonly string Username;
            public readonly string Name;
            public readonly DeviceInfo DeviceInfo;
            public readonly Crypto.OtpInfo OtpInfo;

            public ClientInfo(string username, string name, DeviceInfo deviceInfo, Crypto.OtpInfo otpInfo)
            {
                Username = username;
                Name = name;
                DeviceInfo = deviceInfo;
                OtpInfo = otpInfo;
            }
        }

        // Returns OAuth transaction id that is used in the next step
        public static string AuthStep1(ClientInfo clientInfo, IHttpClient http)
        {
            return Post(http,
                        "https://truekeyapi.intelsecurity.com/session/auth",
                        MakeCommonRequest(clientInfo, "session_id_token"),
                        response => response.StringAt("oAuthTransId"));
        }

        // Returns instructions on what to do next
        public static TwoFactorAuth.Settings AuthStep2(ClientInfo clientInfo,
                                                       string password,
                                                       string transactionId,
                                                       IHttpClient http)
        {
            var parameters = new Dictionary<string, object> {
                {"userData", new Dictionary<string, object> {
                    {"email", clientInfo.Username},
                    {"oAuthTransId", transactionId},
                    {"pwd", Crypto.HashPassword(clientInfo.Username, password)},
                }},
                {"deviceData", new Dictionary<string, object> {
                    {"deviceId", clientInfo.DeviceInfo.Id},
                    {"deviceType", "mac"},
                    {"devicePlatformType", "macos"},
                    {"otpData", RandomOtpChallngeAsDictionary(clientInfo.OtpInfo)},
                }},
            };

            return Post(http,
                        "https://truekeyapi.intelsecurity.com/mp/auth",
                        parameters,
                        ParseAuthStep2Response);
        }

        // Saves the device as trusted. Trusted devices do not need to perform the two
        // factor authentication and log in non-interactively.
        public static void SaveDeviceAsTrusted(ClientInfo clientInfo,
                                               string transactionId,
                                               string oauthToken,
                                               IHttpClient http)
        {
            var parameters = MakeCommonRequest(clientInfo, "code", transactionId);
            ((Dictionary<string, object>)parameters["data"])["dashboardData"]
                = new Dictionary<string, object>
                {
                    {"deviceData", new Dictionary<string, object> {{"isTrusted", true}}},
                };

            Post(http,
                 "https://truekeyapi.intelsecurity.com/sp/dashboard/v2/udt",
                 parameters,
                 new Dictionary<string, string> {{"x-idToken", oauthToken}},
                 response => true);
        }

        // Check if the second factor has been completed by the user.
        // On success returns an OAuth token.
        public static string AuthCheck(ClientInfo clientInfo, string transactionId, IHttpClient http)
        {
            return Post(http,
                        "https://truekeyapi.intelsecurity.com/sp/profile/v1/gls",
                        MakeCommonRequest(clientInfo, "code", transactionId),
                        response =>
                        {
                            if (response.IntAt("nextStep") == 10)
                                return response.StringAt("idToken");

                            throw new FetchException(FetchException.FailureReason.InvalidResponse,
                                                     "Invalid response in AuthCheck, expected an OAuth token");
                        });
        }

        // Send a verification email as a second factor action.
        public static void AuthSendEmail(ClientInfo clientInfo,
                                         string email,
                                         string transactionId,
                                         IHttpClient http)
        {
            var parameters = MakeCommonRequest(clientInfo, "code", transactionId);
            ((Dictionary<string, object>)parameters["data"])["notificationData"]
                = new Dictionary<string, object>
            {
                {"NotificationType", 1},
                {"RecipientId", email},
            };

            Post(http,
                 "https://truekeyapi.intelsecurity.com/sp/oob/v1/son",
                 parameters,
                 response => true);
        }

        // Send a push message to a device as a second factor action.
        public static void AuthSendPush(ClientInfo clientInfo,
                                        string deviceId,
                                        string transactionId,
                                        IHttpClient http)
        {
            var parameters = MakeCommonRequest(clientInfo, "code", transactionId);
            ((Dictionary<string, object>)parameters["data"])["notificationData"]
                = new Dictionary<string, object>
            {
                {"NotificationType", 2},
                {"RecipientId", deviceId},
            };

            Post(http,
                 "https://truekeyapi.intelsecurity.com/sp/oob/v1/son",
                 parameters,
                 response => true);
        }

        // Fetches the vault data, parses and returns in the encrypted form.
        public static EncryptedVault GetVault(string oauthToken, IHttpClient http)
        {
            return Get(http,
                       "https://pm-api.truekey.com/data",
                       new Dictionary<string, string>
                       {
                           {"Authorization", "Bearer " + oauthToken},
                           {"Accept", "application/vnd.tk-pm-api.v1+json"},
                           {"X-TK-Client-API", "TK-API-1.1"},
                           {"X-TK-Client-Version", "2.6.3820"},
                           {"X-TK-Client-Language", "en-US"},
                           {"X-TK-Client-Context", "crx-mac"},
                       },
                       ParseGetVaultResponse);
        }

        //
        // Internal
        //

        internal static TwoFactorAuth.Settings ParseAuthStep2Response(JObject response)
        {
            var nextStep = response.IntAt("riskAnalysisInfo/nextStep");
            var data = response.At("riskAnalysisInfo/nextStepData");

            // Special case: done
            if (nextStep == 10)
                return new TwoFactorAuth.Settings(TwoFactorAuth.Step.Done,
                                                  transactionId: "",
                                                  email: "",
                                                  devices: new TwoFactorAuth.OobDevice[0],
                                                  oAuthToken: response.StringAt("idToken"));

            var transactionId = response.StringAt("oAuthTransId");
            var email = data.StringAt("verificationEmail");

            // Special case: email doesn't need OOB devices
            if (nextStep == 14)
                return new TwoFactorAuth.Settings(TwoFactorAuth.Step.WaitForEmail,
                                                  transactionId: transactionId,
                                                  email: email,
                                                  devices: new TwoFactorAuth.OobDevice[0],
                                                  oAuthToken: "");

            var devices = ParseOobDevices(data.At("oobDevices"));
            if (devices.Length < 1)
                throw new FetchException(FetchException.FailureReason.InvalidResponse,
                                         "At least one OOB device is expected");

            TwoFactorAuth.Step step;
            switch (nextStep)
            {
            case 8:
                step = TwoFactorAuth.Step.Face;
                break;
            case 12:
                step = TwoFactorAuth.Step.WaitForOob;
                break;
            case 13:
                step = TwoFactorAuth.Step.ChooseOob;
                break;
            case 15:
                step = TwoFactorAuth.Step.Fingerprint;
                break;
            default:
                throw new FetchException(FetchException.FailureReason.InvalidResponse,
                    string.Format("Next two factor step {0} is not supported", nextStep));
            }

            return new TwoFactorAuth.Settings(step,
                                              transactionId: transactionId,
                                              email: email,
                                              devices: devices,
                                              oAuthToken: "");
        }

        internal static TwoFactorAuth.OobDevice[] ParseOobDevices(JToken deviceInfo)
        {
            if (deviceInfo.Type != JTokenType.Array)
                return new TwoFactorAuth.OobDevice[0];

            return deviceInfo.Select(i => new TwoFactorAuth.OobDevice(i.StringAt("deviceName"),
                                                                      i.StringAt("deviceId"))).ToArray();
        }

        internal static EncryptedVault ParseGetVaultResponse(JObject response)
        {
            var salt = response.StringAt("customer/salt").DecodeHex();
            var key = response.StringAt("customer/k_kek").Decode64();
            var accounts = response
                .At("assets")
                .Select(i => new EncryptedAccount(
                    id : i.IntAt("id"),
                    name : i.StringAt("name", ""),
                    username : i.StringAt("login", ""),
                    encryptedPassword : (i.StringAt("password_k", "")).Decode64(),
                    url : i.StringAt("url", ""),
                    encryptedNote : (i.StringAt("memo_k", "")).Decode64()))
                .ToArray();

            return new EncryptedVault(salt, key, accounts);
        }

        internal static Dictionary<string, object> MakeCommonRequest(ClientInfo clientInfo,
                                                                     string responseType,
                                                                     string oAuthTransactionId = "")
        {
            return new Dictionary<string, object> {
                {"data", new Dictionary<string, object> {
                    {"contextData", new Dictionary<string, object> {
                        {"deviceInfo", new Dictionary<string, object> {
                            {"deviceName", clientInfo.Name},
                            {"devicePlatformID", 7}, // MacOS (see DevicePlatformType)
                            {"deviceType", 5}, // Mac (see DeviceType)
                        }}
                    }},
                    {"rpData", new Dictionary<string, object> {
                        {"clientId", "42a01655e65147c3b03721df36b45195"},
                        {"response_type", responseType},
                        {"culture", "en-US"},
                    }},
                    {"userData", new Dictionary<string, object> {
                        {"email", clientInfo.Username},
                        {"oTransId", oAuthTransactionId},
                    }},
                    {"ysvcData", new Dictionary<string, object> {
                        {"deviceId", clientInfo.DeviceInfo.Id},
                    }},
                }},
            };
        }

        internal static Dictionary<string, object> RandomOtpChallngeAsDictionary(Crypto.OtpInfo otp)
        {
            var challenge = Crypto.GenerateRandomOtpChallenge(otp);
            return new Dictionary<string, object> {
                {"qn", challenge.Challenge.ToBase64()},
                {"otpType", "time"},
                {"otp", challenge.Signature.ToBase64()},
            };
        }

        // Make a JSON GET request and return the result as parsed JSON.
        internal static T Get<T>(IHttpClient http,
                                 string url,
                                 Dictionary<string, string> headers,
                                 Func<JObject, T> parse)
        {
            var response = Get(http, url, headers);

            try
            {
                return parse(response);
            }
            catch (JTokenAccessException e)
            {
                throw MakeInvalidResponseError("Unexpected format in response from '{0}'", url, e);
            }
        }

        // Make a JSON GET request and return the result as parsed JSON.
        internal static JObject Get(IHttpClient http, string url, Dictionary<string, string> headers)
        {
            return MakeRequest(() => http.Get(url, headers), url);
        }

        // Make a JSON POST request and return the result as parsed JSON.
        // Checks if the operation was successful.
        internal static T Post<T>(IHttpClient http,
                                  string url,
                                  Dictionary<string, object> parameters,
                                  Func<JObject, T> parse)
        {
            return Post(http, url, parameters, new Dictionary<string, string>(), parse);
        }

        // Make a JSON POST request and return the result as parsed JSON.
        // Checks if the operation was successful.
        internal static T Post<T>(IHttpClient http,
                                  string url,
                                  Dictionary<string, object> parameters,
                                  Dictionary<string, string> headers,
                                  Func<JObject, T> parse)
        {
            var response = PostNoCheck(http, url, parameters, headers);

            try
            {
                if (response.BoolAt("responseResult/isSuccess"))
                    return parse(response);
            }
            catch (JTokenAccessException e)
            {
                throw MakeInvalidResponseError("Unexpected format in response from '{0}'", url, e);
            }

            var code = response.StringAt("responseResult/errorCode", "");
            var message = response.StringAt("responseResult/errorDescription", "");
            throw new FetchException(FetchException.FailureReason.RespondedWithError,
                                     string.Format(
                                         "POST request to '{0}' failed with error ({1}: '{2}')",
                                         url,
                                         code,
                                         message));
        }

        // Make a JSON POST request and return the result as parsed JSON.
        internal static JObject PostNoCheck(IHttpClient http,
                                            string url,
                                            Dictionary<string, object> parameters,
                                            Dictionary<string, string> headers)
        {
            return MakeRequest(() => http.Post(url, parameters, headers), url);
        }

        // Make a JSON GET/POST request and return the result as parsed JSON.
        internal static JObject MakeRequest(Func<string> request, string url)
        {
            try
            {
                return JObject.Parse(request());
            }
            catch (WebException e)
            {
                throw MakeNetworkError(url, e);
            }
            catch (JsonException e)
            {
                throw MakeInvalidResponseError("Invalid JSON in response from '{0}'", url, e);
            }
        }

        private static FetchException MakeNetworkError(string url, WebException original)
        {
            if (original.Status != WebExceptionStatus.ProtocolError)
                return new FetchException(FetchException.FailureReason.NetworkError,
                                          string.Format("Request to '{0}' failed", url),
                                          original);


            var response = (HttpWebResponse)original.Response;
            return MakeSpecialHttpError(url, response, original) ??
                   MakeGenericHttpError(url, response, original);
        }

        // Returns null if it's not special.
        // A special error is the one when the status code has a specific meaning.
        private static FetchException MakeSpecialHttpError(string url,
                                                           HttpWebResponse response,
                                                           WebException original)
        {
            if ((int)response.StatusCode != 422)
                return null;

            return new FetchException(FetchException.FailureReason.IncorrectCredentials,
                                      string.Format(
                                          "{0} request to '{1}' failed, most likely username/password are incorrect",
                                          response.Method,
                                          url),
                                      original);
        }

        private static FetchException MakeGenericHttpError(string url,
                                                           HttpWebResponse response,
                                                           WebException original)
        {
            return new FetchException(FetchException.FailureReason.NetworkError,
                                      string.Format("{0} request to '{1}' failed with HTTP status code {2}",
                                                    response.Method,
                                                    url,
                                                    response.StatusCode),
                                      original);
        }

        private static FetchException MakeInvalidResponseError(string format,
                                                               string url,
                                                               Exception original)
        {
            return new FetchException(FetchException.FailureReason.InvalidResponse,
                                      string.Format(format, url),
                                      original);
        }
    }
}
