// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;

namespace RoboForm
{
    // TODO: Move out to its own file
    internal class ClientInfo
    {
        public readonly string Username;
        public readonly string Password;
        public readonly string DeviceId;

        public ClientInfo(string username, string password, string deviceId)
        {
            Username = username;
            Password = password;
            DeviceId = deviceId;
        }
    }

    internal static class Client
    {
        public static Vault OpenVault(ClientInfo clientInfo, Ui ui, IHttpClient http)
        {
            var session = Login(clientInfo, ui, http);
            try
            {
                var blob = GetBlob(clientInfo.Username, session, http);
                var json = OneFile.Parse(blob, clientInfo.Password);
                return VaultParser.Parse(json);
            }
            finally
            {
                Logout(clientInfo.Username, session, http);
            }
        }

        //
        // Internal
        //

        // The simple login process should take only one SCRAM sequence to get finished.
        // The login with 2FA enabled takes three SCRAM sequences.
        // Each SCRAM sequence is a two step request-response dance. See
        // https://en.wikipedia.org/wiki/Salted_Challenge_Response_Authentication_Mechanism
        // for details.
        // The 2FA goes as follows:
        //   1. Get the 2F channel to use (email, SMS, time-based) in response.
        //   2. Trigger the one-time password (OTP) issue on a requested channel. This step
        //      triggers an email or SMS to be sent.
        //   3. Send the OPT and receive the auth cookie.
        // When the password is incorrect we fail on the step 1. When the OTP is incorrect
        // we fail on step 3.

        // This is an internal version of ClientInfo that also contains session specific nonce.
        internal class Credentials
        {
            public readonly string Username;
            public readonly string Password;
            public readonly string DeviceId;
            public readonly string Nonce;

            public Credentials(string username, string password, string deviceId, string nonce)
            {
                Username = username;
                Password = password;
                DeviceId = deviceId;
                Nonce = nonce;
            }

            public Credentials(ClientInfo clientInfo, string nonce)
                : this(clientInfo.Username, clientInfo.Password, clientInfo.DeviceId, nonce)
            {
            }
        }

        internal class OtpOptions
        {
            public readonly string Channel;
            public readonly string Password;
            public readonly bool ShouldRemember;

            public OtpOptions(string channel = null,
                              string password = null,
                              bool shouldRemember = false)
            {
                Channel = channel;
                Password = password;
                ShouldRemember = shouldRemember;
            }
        }

        internal static Session Login(ClientInfo clientInfo, Ui ui, IHttpClient http)
        {
            return Login(new Credentials(clientInfo, GenerateNonce()), ui, http);
        }

        internal static Session Login(Credentials credentials, Ui ui, IHttpClient http)
        {
            // Step 1: Log in or get a name of the 2FA channel (email, sms, totp)
            var sessionOrChannel = PerformScramSequence(credentials, new OtpOptions(), http);

            // Logged in. No 2FA.
            if (sessionOrChannel.Session != null)
                return sessionOrChannel.Session;

            var otpChannel = sessionOrChannel.OtpChannel;

            // Step 2: Trigger OTP issue.
            var shouldBeOtp = PerformScramSequence(credentials, new OtpOptions(otpChannel), http);

            // Should never happen really. But let's see just in case if we got logged in.
            if (shouldBeOtp.Session != null)
                return sessionOrChannel.Session;

            // Ask the UI for the OTP
            var otp = ui.ProvideSecondFactorPassword(otpChannel);

            // Step 3: Send the OTP.
            var shouldBeSession = PerformScramSequence(credentials,
                                                       new OtpOptions(otpChannel,
                                                                      otp.Password,
                                                                      otp.RememberDevice),
                                                       http);

            // We should be really logged in this time.
            if (shouldBeSession.Session != null)
                return shouldBeSession.Session;

            throw new ClientException(ClientException.FailureReason.IncorrectCredentials,
                                      "Incorrect one time password");
        }

        internal class ScramResult
        {
            public readonly Session Session;
            public readonly string OtpChannel;

            public ScramResult(Session session)
            {
                Session = session;
            }

            public ScramResult(string otpChannel)
            {
                OtpChannel = otpChannel;
            }
        }

        internal static ScramResult PerformScramSequence(Credentials credentials,
                                                         OtpOptions otp,
                                                         IHttpClient http)
        {
            // TODO: Shouldn't Step1 return AuthInfo and not a header?
            var header = Step1(credentials, otp, http);
            var authInfo = AuthInfo.Parse(header);
            return Step2(credentials, otp, authInfo, http);
        }

        internal static void Logout(string username, Session session, IHttpClient http)
        {
            using (var response = http.Post(ApiUrl(username, "logout"),
                                            new Dictionary<string, string>
                                            {
                                                {"Cookie", session.Header}
                                            }))
            {
                // TODO: Do we want to abort on the failed logout? If we got here it means we
                //       have a parsed vault and aborting at this stage is gonna prevent the
                //       user from getting it. On the other hand this will help to catch
                //       any bugs in the logout code if the protocol changes. It's important
                //       to log out as the server usually keeps track of open sessions and
                //       might start blocking new sessions at some point.
                if (response.StatusCode != HttpStatusCode.OK)
                    throw MakeNetworkError(response.StatusCode);
            }
        }

        internal static byte[] GetBlob(string username, Session session, IHttpClient http)
        {
            // TODO: Make this random? TBH not sure what it's for.
            var url = string.Format("{0}/user-data.rfo?_{1}", ApiBaseUrl(username), 1337);

            using (var response = http.Get(url,
                                           new Dictionary<string, string>
                                           {
                                               {"Cookie", session.Header}
                                           }))
            {
                if (response.StatusCode != HttpStatusCode.OK)
                    throw MakeNetworkError(response.StatusCode);

                return response.Content.ReadAsByteArrayAsync().Result;
            }
        }

        internal static Dictionary<string, string> ScramHeaders(string authorization,
                                                                string deviceId,
                                                                OtpOptions otp)
        {
            var headers = new Dictionary<string, string>()
            {
                {"Authorization", authorization},
                {"Cookie", string.Format("sib-deviceid={0}", deviceId)},
                {"x-sib-auth-alt-channel", otp.Channel ?? "-"},
            };

            if (otp.Password != null)
            {
                headers["x-sib-auth-alt-otp"] = otp.Password;
                headers["x-sib-auth-alt-memorize"] = otp.ShouldRemember ? "1" : "0";
            }

            return headers;
        }

        internal static string Step1(Credentials credentials, OtpOptions otp, IHttpClient http)
        {
            var headers = ScramHeaders(Step1AuthorizationHeader(credentials),
                                       credentials.DeviceId,
                                       otp);
            using (var response = http.Post(LoginUrl(credentials.Username), headers))
            {
                // Handle this separately not to have a confusing error message on "success".
                // This should never happen as it's not clear what to do after this fake "success".
                // We need both step1 and step2 to complete to get a valid session.
                if (response.IsSuccessStatusCode)
                {
                    var message = string.Format(
                        "Unauthorized (401) is expected in the response, got {0} ({1}) instead",
                        response.StatusCode,
                        (int)response.StatusCode);
                    throw MakeInvalidResponse(message);
                }

                // 401 is expected as the only valid response at this point
                if (response.StatusCode != HttpStatusCode.Unauthorized)
                    throw MakeNetworkError(response.StatusCode);

                // WWW-Authenticate has the result of this step.
                var header = GetHeader(response, "WWW-Authenticate");
                if (string.IsNullOrWhiteSpace(header))
                    throw MakeInvalidResponse("WWW-Authenticate header wasn't found in the response");

                return header;
            }
        }

        internal static ScramResult Step2(Credentials credentials,
                                          OtpOptions otp,
                                          AuthInfo authInfo,
                                          IHttpClient http)
        {
            var headers = ScramHeaders(Step2AuthorizationHeader(credentials, authInfo),
                                       credentials.DeviceId,
                                       otp);
            using (var response = http.Post(LoginUrl(credentials.Username), headers))
            {
                // Step2 fails with 401 on incorrect username or password
                if (response.StatusCode == HttpStatusCode.Unauthorized)
                {
                    var requestedOtpChannel = GetHeader(response, "x-sib-auth-alt-otp");
                    if (!string.IsNullOrWhiteSpace(requestedOtpChannel))
                        return new ScramResult(requestedOtpChannel);

                    // If OTP is set then it's the OTP that is wrong
                    if (otp.Password != null)
                        throw new ClientException(
                            ClientException.FailureReason.IncorrectOneTimePassword,
                            "One time password is incorrect");

                    throw new ClientException(
                        ClientException.FailureReason.IncorrectCredentials,
                        "Username or password is incorrect");
                }

                // Otherwise step2 is supposed to succeed
                if (response.StatusCode != HttpStatusCode.OK)
                    throw MakeNetworkError(response.StatusCode);

                // The server is supposed to return some cookies
                if (!response.Headers.Contains("Set-Cookie"))
                    throw MakeInvalidResponse("No cookies were found in the response");

                // Any URL will do. It's just a key in a hash.
                var cookieUri = new Uri("https://detunized.net");

                // Parse all the cookies and put them in a jar
                var cookieJar = new CookieContainer();
                foreach (var cookie in response.Headers.GetValues("Set-Cookie"))
                    cookieJar.SetCookies(cookieUri, cookie);

                // Extract the cookies we're interested in
                var cookies = cookieJar.GetCookies(cookieUri);

                var auth = cookies["sib-auth"];
                if (auth == null)
                    throw MakeInvalidResponse("'sib-auth' cookie wasn't found in the response");

                var device = cookies["sib-deviceid"];
                if (device == null)
                    throw MakeInvalidResponse("'sib-deviceid' cookie wasn't found in the response");

                return new ScramResult(new Session(auth.Value, device.Value));
            }
        }

        internal static string GenerateNonce()
        {
            return Crypto.RandomBytes(16).ToUrlSafeBase64();
        }

        internal static string Step1AuthorizationHeader(Credentials credentials)
        {
            var data = string.Format("n,,n={0},r={1}",
                                     credentials.Username.EncodeUri(),
                                     credentials.Nonce);
            return string.Format("SibAuth realm=\"RoboForm Online Server\",data=\"{0}\"",
                                 data.ToBase64());
        }

        internal static string Step2AuthorizationHeader(Credentials credentials, AuthInfo authInfo)
        {
            var clientKey = Crypto.ComputeClientKey(credentials.Password, authInfo);
            var clientHash = Crypto.Sha256(clientKey);

            var hashingMaterial = string.Format("n={0},r={1},{2},c=biws,r={3}",
                                                credentials.Username.EncodeUri(),
                                                credentials.Nonce,
                                                authInfo.Data,
                                                authInfo.Nonce);

            var hashed = Crypto.Hmac(clientHash, hashingMaterial.ToBytes());
            var proof = clientKey.Zip(hashed, (a, b) => (byte)(a ^ b)).ToArray();
            var data = string.Format("c=biws,r={0},p={1}", authInfo.Nonce, proof.ToBase64());

            return string.Format("SibAuth sid=\"{0}\",data=\"{1}\"", authInfo.Sid, data.ToBase64());
        }



        internal static string LoginUrl(string username)
        {
            return ApiUrl(username, "login");
        }

        internal static string ApiUrl(string username, string endpoint)
        {
            return string.Format("{0}?{1}", ApiBaseUrl(username), endpoint);
        }

        internal static string ApiBaseUrl(string username)
        {
            return string.Format("https://online.roboform.com/rf-api/{0}", username.EncodeUri());
        }

        internal static string GetHeader(HttpResponseMessage response, string name)
        {
            IEnumerable<string> header;
            if (response.Headers.TryGetValues(name, out header))
                return header.FirstOrDefault();

            return null;
        }

        //
        // Private
        //

        private static ClientException MakeNetworkError(HttpStatusCode code)
        {
            return new ClientException(
                ClientException.FailureReason.NetworkError,
                string.Format("Network request failed with HTTP code {0} ({1})", code, (int)code));
        }

        private static ClientException MakeInvalidResponse(string message)
        {
            return new ClientException(ClientException.FailureReason.InvalidResponse, message);
        }
    }
}
