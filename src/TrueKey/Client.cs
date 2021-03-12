// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
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
                {"policyVersion", 1},
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

            Post<R.Status>("https://id-api.truekey.com/sp/dashboard/v2/udt",
                           parameters,
                           new Dictionary<string, string> {{"x-idToken", oauthToken}},
                           rest);
        }

        // Check if the second factor has been completed by the user.
        // On success returns a valid OAuth token.
        internal static string AuthCheck(ClientInfo clientInfo, string transactionId, RestClient rest)
        {
            var response = Post<R.AuthCheck>("https://id-api.truekey.com/sp/profile/v1/gls",
                                             MakeCommonRequest(clientInfo, "code", transactionId),
                                             rest);
            if (response.NextStep != 10)
                throw MakeError("Invalid response in AuthCheck, expected an OAuth token");

            var token = response.OAuthToken;
            if (token.IsNullOrEmpty())
                throw MakeError("Invalid response in AuthCheck, expected a valid OAuth token");

            return token;
        }

        // Send a verification email as a second factor action.
        internal static void AuthSendEmail(ClientInfo clientInfo,
                                           string email,
                                           string transactionId,
                                           RestClient rest)
        {
            var parameters = MakeCommonRequest(clientInfo, "code", transactionId);
            ((Dictionary<string, object>)parameters["data"])["notificationData"] = new Dictionary<string, object>
            {
                {"NotificationType", 1},
                {"RecipientId", email},
            };

            Post<R.Status>("https://id-api.truekey.com/sp/oob/v1/son", parameters, rest);
        }

        // Send a push message to a device as a second factor action.
        internal static void AuthSendPush(ClientInfo clientInfo,
                                          string deviceId,
                                          string transactionId,
                                          RestClient rest)
        {
            var parameters = MakeCommonRequest(clientInfo, "code", transactionId);
            ((Dictionary<string, object>)parameters["data"])["notificationData"] = new Dictionary<string, object>
            {
                {"NotificationType", 2},
                {"RecipientId", deviceId},
            };

            Post<R.Status>("https://id-api.truekey.com/sp/oob/v1/son", parameters, rest);
        }

        // Fetches the vault data, parses and returns in the encrypted form.
        internal static EncryptedVault GetVault(string oauthToken, RestClient rest)
        {
            var response = Get<R.Vault>("https://pm-api.truekey.com/data",
                                        new Dictionary<string, string>
                                        {
                                            {"Authorization", "Bearer " + oauthToken},
                                            {"Accept", "application/vnd.tk-pm-api.v1+json"},
                                            {"X-TK-Client-API", "TK-API-1.1"},
                                            {"X-TK-Client-Version", "2.6.3820"},
                                            {"X-TK-Client-Language", "en-US"},
                                            {"X-TK-Client-Context", "crx-mac"},
                                        },
                                        rest);
            return ParseGetVaultResponse(response);
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
            var email = data.VerificationEmail ?? "";

            // Special case: email doesn't need OOB devices
            if (nextStep == 14)
                return new TwoFactorAuth.Settings(TwoFactorAuth.Step.WaitForEmail,
                                                  transactionId: transactionId,
                                                  email: email,
                                                  devices: new TwoFactorAuth.OobDevice[0],
                                                  oAuthToken: "");

            var devices = (data.OobDevices ?? new R.OobDevice[0])
                .Select(x => new TwoFactorAuth.OobDevice(name: x.Name, id: x.Id))
                .ToArray();

            if (devices.Length < 1)
                throw MakeError("At least one OOB device is expected");

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
                throw MakeError($"Next two factor step {nextStep} is not supported");
            }

            return new TwoFactorAuth.Settings(step,
                                              transactionId: transactionId,
                                              email: email,
                                              devices: devices,
                                              oAuthToken: "");
        }

        internal static EncryptedVault ParseGetVaultResponse(R.Vault response)
        {
            var salt = response.Customer.Salt.DecodeHex();
            var key = response.Customer.Kek.Decode64();

            var accounts = response
                .Accounts
                .Select(i => new EncryptedAccount(id: i.Id,
                                                  name: i.Name ?? "",
                                                  username: i.Username ?? "",
                                                  encryptedPassword: (i.EncryptedPassword ?? "").Decode64(),
                                                  url: i.Url ?? "",
                                                  encryptedNote: (i.EncryptedNote ?? "").Decode64()))
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
                    {"policyVersion", 1},
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

       internal static T Get<T>(string url, Dictionary<string, string> headers, RestClient rest)
       {
           var response = rest.Get<T>(url, headers);
           if (response.IsSuccessful)
               return response.Data;

           throw MakeNetworkError(response);
       }

        internal static T Post<T>(string url, Dictionary<string, object> parameters, RestClient rest) where T : R.Status
        {
            return Post<T>(url, parameters, RestClient.NoHeaders, rest);
        }

        internal static T Post<T>(string url,
                                  Dictionary<string, object> parameters,
                                  Dictionary<string, string> headers,
                                  RestClient rest) where T : R.Status
        {
            var response = rest.PostJson<T>(url, parameters, headers);
            if (!response.IsSuccessful)
                throw MakeNetworkError(response);

            var result = response.Data.Result;
            if (result.IsSuccess)
                return response.Data;

            var code = result.ErrorCode ?? "unknown";
            var description = result.ErrorDescription ?? "Unknown error";

            throw MakeError($"POST request to '{url}' failed with error ({code}: '{description}')");
        }

        //
        // Private
        //

        private static BaseException MakeNetworkError(RestResponse<string> response)
        {
            if (response.IsNetworkError)
                return new NetworkErrorException("Network error occurred", response.Error);

            if ((int)response.StatusCode == 422)
                return new BadCredentialsException(
                    $"HTTP request to '{response.RequestUri}' failed, most likely username/password are incorrect",
                    response.Error);

            if (response.StatusCode != HttpStatusCode.OK)
                return new InternalErrorException(
                    $"Request to '{response.RequestUri}' failed with HTTP status {(int)response.StatusCode}",
                    response.Error);

            return new InternalErrorException($"Request to '{response.RequestUri}' failed", response.Error);
        }

        private static InternalErrorException MakeError(string message, Exception inner = null)
        {
            return new InternalErrorException(message, inner);
        }
    }
}
