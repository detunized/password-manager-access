// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Newtonsoft.Json.Linq;

namespace TrueKey
{
    public static class Remote
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
        public static DeviceInfo RegisetNewDevice(string deviceName)
        {
            return RegisetNewDevice(deviceName, new HttpClient());
        }

        public class OtpInfo
        {
            public readonly int Version;
            public readonly int OtpAlgorithm;
            public readonly int OtpLength;
            public readonly int HashAlgorithm;
            public readonly int TimeStep;
            public readonly uint StartTime;
            public readonly byte[] Suite;
            public readonly byte[] HmacSeed;
            public readonly byte[] Iptmk;

            public OtpInfo(int version,
                           int otpAlgorithm,
                           int otpLength,
                           int hashAlgorithm,
                           int timeStep,
                           uint startTime,
                           byte[] suite,
                           byte[] hmacSeed,
                           byte[] iptmk)
            {
                Version = version;
                OtpAlgorithm = otpAlgorithm;
                OtpLength = otpLength;
                HashAlgorithm = hashAlgorithm;
                TimeStep = timeStep;
                StartTime = startTime;
                Suite = suite;
                HmacSeed = hmacSeed;
                Iptmk = iptmk;
            }
        }

        // Parses clientToken field returned by the server. It contains encoded
        // OCRA/OPT/RFC 6287 information. This is used later on to sign messages.
        public static OtpInfo ParseClientToken(string encodedToken)
        {
            using (var s = new MemoryStream(encodedToken.Decode64()))
            using (var r = new BinaryReader(s))
            {
                var tokenType = r.ReadByte();
                var tokenLength = r.ReadUInt16BigEndian();
                var token = r.ReadBytes(tokenLength);
                var iptmkTag = r.ReadByte();
                var iptmkLength = r.ReadUInt16BigEndian();
                var iptmk = r.ReadBytes(iptmkLength);

                using (var ts = new MemoryStream(token))
                using (var tr = new BinaryReader(ts))
                {
                    var version = tr.ReadByte();
                    var otpAlgorithm = tr.ReadByte();
                    var otpLength = tr.ReadByte();
                    var hashAlgorithm = tr.ReadByte();
                    var timeStep = tr.ReadByte();
                    var startTime = tr.ReadUInt32BigEndian();
                    var serverTime = tr.ReadUInt32BigEndian();
                    var wysOption = tr.ReadByte();
                    var suiteLength = tr.ReadUInt16BigEndian();
                    var suite = tr.ReadBytes(suiteLength);

                    ts.Position = 128;
                    var hmacSeedLength = tr.ReadUInt16BigEndian();
                    var hmacSeed = tr.ReadBytes(hmacSeedLength);

                    return new OtpInfo(version: version,
                                       otpAlgorithm: otpAlgorithm,
                                       otpLength: otpLength,
                                       hashAlgorithm: hashAlgorithm,
                                       timeStep: timeStep,
                                       startTime: startTime,
                                       suite: suite,
                                       hmacSeed: hmacSeed,
                                       iptmk: iptmk);
                }
            }
        }

        // Checks that the OTP info is something we can work with. The Chrome
        // extension also supports only this subset. They don't validate as much,
        // just assume the values are what they expect.
        public static void ValidateOtpInfo(OtpInfo otp)
        {
            Action<object, object, string> throwError = (actual, expected, name) =>
            {
                throw new ArgumentException(
                    string.Format("Invalid OTP {0} (expected {1}, got {2})",
                                  name,
                                  expected,
                                  actual));
            };

            Action<int, int, string> verify = (actual, expected, name) =>
            {
                if (actual != expected)
                    throwError(actual, expected, name);
            };

            verify(otp.Version, 3, "version");
            verify(otp.OtpAlgorithm, 1, "algorithm");
            verify(otp.OtpLength, 0, "length");
            verify(otp.HashAlgorithm, 2, "hash");
            verify(otp.HmacSeed.Length, 32, "HMAC length");
            verify(otp.Iptmk.Length, 32, "IPTMK length");

            const string suite = "OCRA-1:HOTP-SHA256-0:QA08";
            if (!otp.Suite.SequenceEqual(suite.ToBytes()))
                throwError(otp.Suite, suite, "suite");
        }

        public class ClientInfo
        {
            public readonly string Username;
            public readonly string Name;
            public readonly DeviceInfo DeviceInfo;
            public readonly OtpInfo OtpInfo;

            public ClientInfo(string username, string name, DeviceInfo deviceInfo, OtpInfo otpInfo)
            {
                Username = username;
                Name = name;
                DeviceInfo = deviceInfo;
                OtpInfo = otpInfo;
            }
        }

        // Returns OAuth transaction id that is used in the next step
        public static string AuthStep1(ClientInfo clientInfo)
        {
            return AuthStep1(clientInfo, new HttpClient());
        }

        // Returns instructions on what to do next
        public static TwoFactorAuth.Settings AuthStep2(ClientInfo clientInfo,
                                                       string password,
                                                       string transactionId)
        {
            return AuthStep2(clientInfo, password, transactionId, new HttpClient());
        }

        //
        // Internal
        //

        internal static DeviceInfo RegisetNewDevice(string deviceName, IHttpClient http)
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

        internal static string AuthStep1(ClientInfo clientInfo, IHttpClient http)
        {
            var response = Post(http,
                                "https://truekeyapi.intelsecurity.com/session/auth",
                                MakeCommonRequest(clientInfo, "session_id_token"));

            // TODO: Verify results
            return response.StringAtOrNull("oAuthTransId");
        }

        internal static TwoFactorAuth.Settings AuthStep2(ClientInfo clientInfo,
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

        internal static string AuthCheck(ClientInfo clientInfo, IHttpClient http)
        {
            // TODO: Implement this
            return "OAuthToken";
        }

        internal static void AuthSendEmail(ClientInfo clientInfo,
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

        internal static void AuthSendPush(ClientInfo clientInfo,
                                          string deviceId,
                                          string transactionId,
                                          IHttpClient http)
        {
            // TODO: Implement this
        }

        internal static TwoFactorAuth.Settings ParseAuthStep2Response(JObject response)
        {
            // TODO: Make JToken.At* throw some custom exception and don't use OrNull
            //       Catch it and rethrow as invalid response.

            var nextStep = response.IntAtOrNull("riskAnalysisInfo/nextStep");
            var data = response.AtOrNull("riskAnalysisInfo/nextStepData");

            if (nextStep == null || data == null)
                throw new InvalidOperationException("Invalid response");

            switch (nextStep.Value)
            {
            case 10:
                return new TwoFactorAuth.Settings(TwoFactorAuth.Step.Done,
                                                  transactionId: "",
                                                  email: "",
                                                  devices: new TwoFactorAuth.OobDevice[0],
                                                  oAuthToken: response.StringAtOrNull("idToken"));
            case 12:
                return new TwoFactorAuth.Settings(TwoFactorAuth.Step.WaitForOob,
                                                  transactionId: response.StringAt("oAuthTransId"),
                                                  email: data.StringAt("verificationEmail"),
                                                  devices: ParseOobDevices(data.At("oobDevices")),
                                                  oAuthToken: "");
            case 13:
                return new TwoFactorAuth.Settings(TwoFactorAuth.Step.ChooseOob,
                                                  transactionId: response.StringAt("oAuthTransId"),
                                                  email: data.StringAt("verificationEmail"),
                                                  devices: ParseOobDevices(data.At("oobDevices")),
                                                  oAuthToken: "");
            case 14:
                return new TwoFactorAuth.Settings(TwoFactorAuth.Step.WaitForEmail,
                                                  transactionId: response.StringAt("oAuthTransId"),
                                                  email: data.StringAt("verificationEmail"),
                                                  devices : new TwoFactorAuth.OobDevice[0],
                                                  oAuthToken: "");
            }

            throw new InvalidOperationException(
                string.Format("Next two factor step {0} is not supported", nextStep));
        }

        internal static TwoFactorAuth.OobDevice[] ParseOobDevices(JToken deviceInfo)
        {
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

        internal static Dictionary<string, object> RandomOtpChallngeAsDictionary(OtpInfo otp)
        {
            var challenge = Crypto.GenerateRandomOtpChallenge(otp);
            return new Dictionary<string, object> {
                {"qn", challenge.Challenge.ToBase64()},
                {"otpType", "time"},
                {"otp", challenge.Signature.ToBase64()},
            };
        }

        internal static JObject Post(IHttpClient http, string url, Dictionary<string, object> parameters)
        {
            // TODO: Handle network errors
            var response = http.Post(url, parameters);
            var parsed = JObject.Parse(response);

            var success = parsed.AtOrNull("responseResult/isSuccess");
            if (success == null || (bool?)success != true)
                // TODO: Use custom exception
                throw new InvalidOperationException("Operation failed");

            return parsed;
        }
    }
}
