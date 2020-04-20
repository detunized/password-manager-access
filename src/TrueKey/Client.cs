// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.TrueKey
{
    using R = Response;

    internal static class Client
    {
        public static Account[] OpenVault(string username,
                                          string password,
                                          Ui ui,
                                          ISecureStorage storage,
                                          IRestTransport transport)
        {
            var rest = new RestClient(transport);

            // Step 1: Register a new deice or use the existing one from the previous run.
            var deviceInfo = LoadDeviceInfo(storage) ?? RegisterNewDevice("truekey-sharp", rest);

            // Step 2: Parse the token to decode OTP information.
            var otpInfo = Util.ParseClientToken(deviceInfo.Token);

            // Step 3: Validate the OTP info to make sure it's got only the
            //         things we support at the moment.
            Util.ValidateOtpInfo(otpInfo);

            // Store the token and ID for the next time.
            StoreDeviceInfo(deviceInfo, storage);

            // Bundle up everything in one place
            var clientInfo = new ClientInfo(username, "truekey-sharp", deviceInfo, otpInfo);

            // Step 4: Auth step 1 gives us a transaction id to pass along to the next step.
            var transactionId = AuthStep1(clientInfo, rest);

            // Step 5: Auth step 2 gives us the instructions on what to do next. For a new client that
            //         would be some form of second factor auth. For a known client that would be a
            //         pair of OAuth tokens.
            var whatsNext = AuthStep2(clientInfo, password, transactionId, rest);

            // The device is trusted if it's already authenticated at this point and
            // no second factor is needed.
            var isTrusted = whatsNext.IsAuthenticated;

            // Step 6: Auth FSM -- walk through all the auth steps until we're done.
            var oauthToken = TwoFactorAuth.Start(clientInfo, whatsNext, ui, rest);

            // Step 7: Save this device as trusted not to repeat the two factor dance next times.
            if (!isTrusted)
                SaveDeviceAsTrusted(clientInfo, transactionId, oauthToken, rest);

            // Step 8: Get the vault from the server.
            var encryptedVault = GetVault(oauthToken, rest);

            // Step 9: Compute the master key.
            var masterKey = Util.DecryptMasterKey(password,
                                                  encryptedVault.MasterKeySalt,
                                                  encryptedVault.EncryptedMasterKey);

            // Step 10: Decrypt the accounts.
            var accounts = encryptedVault
                .EncryptedAccounts
                .Select(i => new Account(id: i.Id,
                                         name: i.Name,
                                         username: i.Username,
                                         password: Util.Decrypt(masterKey, i.EncryptedPassword).ToUtf8(),
                                         url: i.Url,
                                         note: Util.Decrypt(masterKey, i.EncryptedNote).ToUtf8()))
                .ToArray();

            return accounts;
        }

        //
        // Internal
        //

        internal class DeviceInfo
        {
            public readonly string Token;
            public readonly string Id;

            public DeviceInfo(string token, string id)
            {
                Token = token;
                Id = id;
            }
        }

        internal static DeviceInfo LoadDeviceInfo(ISecureStorage storage)
        {
            var token = storage.LoadString("token");
            var id = storage.LoadString("id");

            if (string.IsNullOrWhiteSpace(token) || string.IsNullOrWhiteSpace(id))
                return null;

            return new DeviceInfo(token, id);
        }

        internal static void StoreDeviceInfo(DeviceInfo deviceInfo, ISecureStorage storage)
        {
            storage.StoreString("token", deviceInfo.Token);
            storage.StoreString("id", deviceInfo.Id);
        }


        // This is the first step in authentication process for a new device.
        // This requests the client token with is used in OCRA (RFC 6287) exchange
        // later on. There's also a server assigned id for the new device.
        //
        // `deviceName` is the name of the device registered with the True Key service.
        // For example 'Chrome' or 'Nexus 5'.
        internal static DeviceInfo RegisterNewDevice(string deviceName, RestClient rest)
        {
            var response = Post<R.RegisterNewDevice>("https://id-api.truekey.com/sp/pabe/v2/so",
                                                     new Dictionary<string, object>
                                                     {
                                                         {"clientUDID", "truekey-sharp"},
                                                         {"deviceName", deviceName},
                                                         {"devicePlatformID", 7},
                                                         {"deviceType", 5},
                                                         {"oSName", "Unknown"},
                                                         {"oathTokenType", 1},
                                                     },
                                                     rest);

            return new DeviceInfo(response.ClientToken, response.DeviceId);
        }

        internal class ClientInfo
        {
            public readonly string Username;
            public readonly string Name;
            public readonly DeviceInfo DeviceInfo;
            public readonly Util.OtpInfo OtpInfo;

            public ClientInfo(string username, string name, DeviceInfo deviceInfo, Util.OtpInfo otpInfo)
            {
                Username = username;
                Name = name;
                DeviceInfo = deviceInfo;
                OtpInfo = otpInfo;
            }
        }

        // Returns OAuth transaction id that is used in the next step
        internal static string AuthStep1(ClientInfo clientInfo, RestClient rest)
        {
            var response = Post<R.AuthStep1>("https://id-api.truekey.com/session/auth",
                                             MakeCommonRequest(clientInfo, "session_id_token"),
                                             rest);

            return response.TransactionId;
        }

        // Returns instructions on what to do next
        internal static TwoFactorAuth.Settings AuthStep2(ClientInfo clientInfo,
                                                         string password,
                                                         string transactionId,
                                                         RestClient rest)
        {
            var parameters = new Dictionary<string, object> {
                {"userData", new Dictionary<string, object> {
                    {"email", clientInfo.Username},
                    {"oAuthTransId", transactionId},
                    {"pwd", Util.HashPassword(clientInfo.Username, password)},
                }},
                {"deviceData", new Dictionary<string, object> {
                    {"deviceId", clientInfo.DeviceInfo.Id},
                    {"deviceType", "mac"},
                    {"devicePlatformType", "macos"},
                    {"otpData", RandomOtpChallngeAsDictionary(clientInfo.OtpInfo)},
                }},
            };

            var response = Post<R.AuthStep2>("https://id-api.truekey.com/mp/auth", parameters, rest);
            return ParseAuthStep2Response(response);
        }

        // Saves the device as trusted. Trusted devices do not need to perform the two
        // factor authentication and log in non-interactively.
        internal static void SaveDeviceAsTrusted(ClientInfo clientInfo,
                                                 string transactionId,
                                                 string oauthToken,
                                                 RestClient rest)
        {
            var parameters = MakeCommonRequest(clientInfo, "code", transactionId);
            ((Dictionary<string, object>) parameters["data"])["dashboardData"] = new Dictionary<string, object>
            {
                {"deviceData", new Dictionary<string, object> {{"isTrusted", true}}},
            };

            Post(rest,
                 "https://id-api.truekey.com/sp/dashboard/v2/udt",
                 parameters,
                 new Dictionary<string, string> {{"x-idToken", oauthToken}},
                 response => true);
        }

        // Check if the second factor has been completed by the user.
        // On success returns an OAuth token.
        internal static string AuthCheck(ClientInfo clientInfo, string transactionId, RestClient rest)
        {
            return Post(rest,
                        "https://id-api.truekey.com/sp/profile/v1/gls",
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
        internal static void AuthSendEmail(ClientInfo clientInfo,
                                           string email,
                                           string transactionId,
                                           RestClient rest)
        {
            var parameters = MakeCommonRequest(clientInfo, "code", transactionId);
            ((Dictionary<string, object>)parameters["data"])["notificationData"]
                = new Dictionary<string, object>
            {
                {"NotificationType", 1},
                {"RecipientId", email},
            };

            Post(rest,
                 "https://id-api.truekey.com/sp/oob/v1/son",
                 parameters,
                 response => true);
        }

        // Send a push message to a device as a second factor action.
        internal static void AuthSendPush(ClientInfo clientInfo,
                                          string deviceId,
                                          string transactionId,
                                          RestClient rest)
        {
            var parameters = MakeCommonRequest(clientInfo, "code", transactionId);
            ((Dictionary<string, object>)parameters["data"])["notificationData"]
                = new Dictionary<string, object>
            {
                {"NotificationType", 2},
                {"RecipientId", deviceId},
            };

            Post(rest,
                 "https://id-api.truekey.com/sp/oob/v1/son",
                 parameters,
                 response => true);
        }

        // Fetches the vault data, parses and returns in the encrypted form.
        internal static EncryptedVault GetVault(string oauthToken, RestClient rest)
        {
            return Get(rest,
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

        internal static TwoFactorAuth.Settings ParseAuthStep2Response(R.AuthStep2 response)
        {
            var nextStep = response.Info.NextStep;
            var data = response.Info.Data;

            // Special case: done
            if (nextStep == 10)
                return new TwoFactorAuth.Settings(initialStep: TwoFactorAuth.Step.Done,
                                                  transactionId: "",
                                                  email: "",
                                                  devices: new TwoFactorAuth.OobDevice[0],
                                                  oAuthToken: response.OAuthToken ?? "");

            var transactionId = response.TransactionId;
            var email = data.VerificationEmail;

            // Special case: email doesn't need OOB devices
            if (nextStep == 14)
                return new TwoFactorAuth.Settings(TwoFactorAuth.Step.WaitForEmail,
                                                  transactionId: transactionId,
                                                  email: email,
                                                  devices: new TwoFactorAuth.OobDevice[0],
                                                  oAuthToken: "");

            var devices = data.OobDevices.Select(x => new TwoFactorAuth.OobDevice(name: x.Name, id: x.Id)).ToArray();
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
                                         $"Next two factor step {nextStep} is not supported");
            }

            return new TwoFactorAuth.Settings(step,
                                              transactionId: transactionId,
                                              email: email,
                                              devices: devices,
                                              oAuthToken: "");
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

        internal static Dictionary<string, object> RandomOtpChallngeAsDictionary(Util.OtpInfo otp)
        {
            var challenge = Util.GenerateRandomOtpChallenge(otp);
            return new Dictionary<string, object> {
                {"qn", challenge.Challenge.ToBase64()},
                {"otpType", "time"},
                {"otp", challenge.Signature.ToBase64()},
            };
        }

        // Make a JSON GET request and return the result as parsed JSON.
        internal static T Get<T>(RestClient rest,
                                 string url,
                                 Dictionary<string, string> headers,
                                 Func<JObject, T> parse)
        {
            var response = Get(rest, url, headers);

            try
            {
                return parse(response);
            }
            catch (JTokenAccessException e)
            {
                throw MakeInvalidResponseError($"Unexpected format in response from '{url}'", e);
            }
        }

        // Make a JSON GET request and return the result as parsed JSON.
        internal static JObject Get(RestClient rest, string url, Dictionary<string, string> headers)
        {
            return MakeRequest(() => rest.Get(url, headers), url);
        }

        // Make a JSON POST request and return the result as parsed JSON.
        // Checks if the operation was successful.
        internal static T Post<T>(RestClient rest,
                                  string url,
                                  Dictionary<string, object> parameters,
                                  Func<JObject, T> parse)
        {
            return Post(rest, url, parameters, new Dictionary<string, string>(), parse);
        }

        internal static T Post<T>(string url, Dictionary<string, object> parameters, RestClient rest) where T : R.Status
        {
            var response = rest.PostJson<T>(url, parameters);
            if (!response.IsSuccessful)
                throw MakeNetworkError(response);

            var result = response.Data.Result;
            if (result.IsSuccess)
                return response.Data;

            var code = result.ErrorCode ?? "unknown";
            var description = result.ErrorDescription ?? "Unknown error";

            throw new FetchException(FetchException.FailureReason.RespondedWithError,
                                     $"POST request to '{url}' failed with error ({code}: '{description}')");
        }

        // Make a JSON POST request and return the result as parsed JSON.
        // Checks if the operation was successful.
        internal static T Post<T>(RestClient rest,
                                  string url,
                                  Dictionary<string, object> parameters,
                                  Dictionary<string, string> headers,
                                  Func<JObject, T> parse)
        {
            var response = PostNoCheck(rest, url, parameters, headers);

            try
            {
                if (response.BoolAt("responseResult/isSuccess"))
                    return parse(response);
            }
            catch (JTokenAccessException e)
            {
                throw MakeInvalidResponseError($"Unexpected format in response from '{url}'", e);
            }

            var code = response.StringAt("responseResult/errorCode", "");
            var message = response.StringAt("responseResult/errorDescription", "");
            throw new FetchException(FetchException.FailureReason.RespondedWithError,
                                     $"POST request to '{url}' failed with error ({code}: '{message}')");
        }

        // Make a JSON POST request and return the result as parsed JSON.
        internal static JObject PostNoCheck(RestClient rest,
                                            string url,
                                            Dictionary<string, object> parameters,
                                            Dictionary<string, string> headers)
        {
            return MakeRequest(() => rest.PostJson(url, parameters, headers), url);
        }

        // Make a JSON GET/POST request and return the result as parsed JSON.
        internal static JObject MakeRequest(Func<RestResponse<string>> request, string url)
        {
            try
            {
                var response = request();
                if (response.IsSuccessful)
                    return JObject.Parse(response.Content);

                throw MakeNetworkError(response);
            }
            catch (JsonException e)
            {
                throw MakeInvalidResponseError($"Invalid JSON in response from '{url}'", e);
            }
        }

        //
        // Private
        //

        private static FetchException MakeNetworkError(RestResponse<string> response)
        {
            if ((int)response.StatusCode == 422)
                return new FetchException(
                    FetchException.FailureReason.IncorrectCredentials,
                    $"HTTP request to '{response.RequestUri}' failed, most likely username/password are incorrect",
                    response.Error);

            return new FetchException(FetchException.FailureReason.NetworkError,
                                      $"Request to '{response.RequestUri}' failed",
                                      response.Error);
        }

        private static FetchException MakeNetworkError(string url, WebException original)
        {
            if (original.Status != WebExceptionStatus.ProtocolError)
                return new FetchException(FetchException.FailureReason.NetworkError,
                                          $"Request to '{url}' failed",
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

            return new FetchException(
                FetchException.FailureReason.IncorrectCredentials,
                $"{response.Method} request to '{url}' failed, most likely username/password are incorrect",
                original);
        }

        private static FetchException MakeGenericHttpError(string url,
                                                           HttpWebResponse response,
                                                           WebException original)
        {
            return new FetchException(
                FetchException.FailureReason.NetworkError,
                $"{response.Method} request to '{url}' failed with HTTP status code {response.StatusCode}",
                original);
        }

        private static FetchException MakeInvalidResponseError(string message, Exception original)
        {
            return new FetchException(FetchException.FailureReason.InvalidResponse, message, original);
        }
    }
}
