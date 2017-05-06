// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Linq;
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
            var response = Post(http,
                                "https://truekeyapi.intelsecurity.com/sp/pabe/v2/so",
                                new Dictionary<string, object>
                                {
                                    {"clientUDID", "truekey-sharp"},
                                    {"deviceName", deviceName},
                                    {"devicePlatformID", 7},
                                    {"deviceType", 5},
                                    {"oSName", "Unknown"},
                                    {"oathTokenType", 1},
                                });

            // TODO: Verify results
            return new DeviceInfo(response.StringAtOrNull("clientToken"),
                                  response.StringAtOrNull("tkDeviceId"));
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
            var response = Post(http,
                                "https://truekeyapi.intelsecurity.com/session/auth",
                                MakeCommonRequest(clientInfo, "session_id_token"));

            // TODO: Verify results
            return response.StringAtOrNull("oAuthTransId");
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

            var response = Post(http,
                                "https://truekeyapi.intelsecurity.com/mp/auth",
                                parameters);

            return ParseAuthStep2Response(response);
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
                 new Dictionary<string, string> {{"x-idToken", oauthToken}});
        }

        // Check if the second factor has been completed by the user.
        // The result either a success or pending when everything go normally.
        public static string AuthCheck(ClientInfo clientInfo, string transactionId, IHttpClient http)
        {
            var response = PostNoCheck(http,
                                       "https://truekeyapi.intelsecurity.com/sp/profile/v1/gls",
                                       MakeCommonRequest(clientInfo, "code", transactionId));

            var success = response.At("responseResult/isSuccess");
            var nextStep = response.IntAt("nextStep");

            if (success != null && (bool?)success == true && nextStep == 10)
                return response.StringAt("idToken");

            // TODO: Don't throw, rather return a negative result
            throw new InvalidOperationException("AuthCheck failed");
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

            Post(http, "https://truekeyapi.intelsecurity.com/sp/oob/v1/son", parameters);
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

            Post(http, "https://truekeyapi.intelsecurity.com/sp/oob/v1/son", parameters);
        }

        public static EncryptedVault GetVault(string oauthToken, IHttpClient http)
        {
            var response = Get(http,
                               "https://pm-api.truekey.com/data",
                               new Dictionary<string, string>
                               {
                                   {"Authorization", "Bearer " + oauthToken},
                                   {"Accept", "application/vnd.tk-pm-api.v1+json"},
                                   {"X-TK-Client-API", "TK-API-1.1"},
                                   {"X-TK-Client-Version", "2.6.3820"},
                                   {"X-TK-Client-Language", "en-US"},
                                   {"X-TK-Client-Context", "crx-mac"},
                               });

            var salt = response.StringAt("customer/salt").DecodeHex();
            var key = response.StringAt("customer/k_kek").Decode64();
            var accounts = response
                .At("assets")
                .Select(i => new EncryptedAccount(
                    id: i.IntAt("id"),
                    name: i.StringAtOrNull("name") ?? "",
                    username: i.StringAtOrNull("login") ?? "",
                    encryptedPassword: (i.StringAtOrNull("password_k") ?? "").Decode64(),
                    url: i.StringAtOrNull("url") ?? "",
                    encryptedNote: (i.StringAtOrNull("memo_k") ?? "").Decode64()))
                .ToArray();

            return new EncryptedVault(salt, key, accounts);
        }

        //
        // Internal
        //

        internal static TwoFactorAuth.Settings ParseAuthStep2Response(JObject response)
        {
            // TODO: Make JToken.At* throw some custom exception and don't use OrNull
            //       Catch it and rethrow as invalid response.

            var nextStep = response.IntAtOrNull("riskAnalysisInfo/nextStep");
            var data = response.AtOrNull("riskAnalysisInfo/nextStepData");

            if (nextStep == null || data == null)
                throw new InvalidOperationException("Invalid response");

            // Special case: done
            if (nextStep.Value == 10)
                return new TwoFactorAuth.Settings(TwoFactorAuth.Step.Done,
                                                  transactionId: "",
                                                  email: "",
                                                  devices: new TwoFactorAuth.OobDevice[0],
                                                  oAuthToken: response.StringAt("idToken"));

            var transactionId = response.StringAt("oAuthTransId");
            var email = data.StringAt("verificationEmail");

            // Special case: email doesn't need OOB devices
            if (nextStep.Value == 14)
                return new TwoFactorAuth.Settings(TwoFactorAuth.Step.WaitForEmail,
                                                  transactionId: transactionId,
                                                  email: email,
                                                  devices: new TwoFactorAuth.OobDevice[0],
                                                  oAuthToken: "");

            var devices = ParseOobDevices(data.At("oobDevices"));
            if (devices.Length < 1)
                throw new InvalidOperationException("Invalid response: at least one OOB device is expected");

            TwoFactorAuth.Step step;
            switch (nextStep.Value)
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
                throw new InvalidOperationException(
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

        internal static JObject Get(IHttpClient http, string url, Dictionary<string, string> headers)
        {
            // TODO: Handle network errors
            var response = http.Get(url, headers);
            return JObject.Parse(response);
        }

        internal static JObject Post(IHttpClient http,
                                     string url,
                                     Dictionary<string, object> parameters)
        {
            return Post(http, url, parameters, new Dictionary<string, string>());
        }

        internal static JObject Post(IHttpClient http,
                                     string url,
                                     Dictionary<string, object> parameters,
                                     Dictionary<string, string> headers)
        {
            var response = PostNoCheck(http, url, parameters, headers);

            var success = response.AtOrNull("responseResult/isSuccess");
            if (success == null || (bool?)success != true)
                // TODO: Use custom exception
                throw new InvalidOperationException("Operation failed");

            return response;
        }

        internal static JObject PostNoCheck(IHttpClient http,
                                            string url,
                                            Dictionary<string, object> parameters)
        {
            return PostNoCheck(http, url, parameters, new Dictionary<string, string>());
        }

        internal static JObject PostNoCheck(IHttpClient http,
                                            string url,
                                            Dictionary<string, object> parameters,
                                            Dictionary<string, string> headers)
        {
            // TODO: Handle network errors
            var response = http.Post(url, parameters, headers);
            return JObject.Parse(response);
        }
    }
}
