// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using Newtonsoft.Json;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.RoboForm
{
    using R = Response;

    internal static class Client
    {
        public static Account[] OpenVault(ClientInfo clientInfo, Ui ui, IRestTransport transport)
        {
            var rest = new RestClient(transport, ApiBaseUrl(clientInfo.Username));
            var session = Login(clientInfo, ui, rest);
            try
            {
                // Open the main user's vault
                var (accounts, privateKey) = OpenFolder(session, clientInfo.Password, "", rest);

                // Open all the folders shared with the user
                if (privateKey != null)
                    foreach (var info in GetSharedFolderList(session, rest))
                        accounts.AddRange(OpenSharedFolder(info, session, privateKey.Value, transport));

                return accounts.ToArray();
            }
            finally
            {
                Logout(session, rest);
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
                : this(clientInfo.Username, clientInfo.Password, clientInfo.DeviceId, nonce) { }
        }

        internal class OtpOptions
        {
            public readonly string Channel;
            public readonly string Password;
            public readonly bool RememberMe;

            public OtpOptions(string channel = null, string password = null, bool rememberMe = false)
            {
                Channel = channel;
                Password = password;
                RememberMe = rememberMe;
            }
        }

        internal static Session Login(ClientInfo clientInfo, Ui ui, RestClient rest)
        {
            return Login(new Credentials(clientInfo, GenerateNonce()), ui, rest);
        }

        internal static Session Login(Credentials credentials, Ui ui, RestClient rest)
        {
            // Step 1: Log in or get a name of the 2FA channel (email, sms, totp)
            var sessionOrChannel = PerformScramSequence(credentials, new OtpOptions(), rest);

            // Logged in. No 2FA.
            if (sessionOrChannel.Session != null)
                return sessionOrChannel.Session;

            var otpChannel = sessionOrChannel.OtpChannel;

            // Step 2: Trigger OTP issue.
            var shouldBeOtp = PerformScramSequence(credentials, new OtpOptions(otpChannel), rest);

            // Should never happen really. But let's see just in case if we got logged in.
            if (shouldBeOtp.Session != null)
                return sessionOrChannel.Session;

            // Ask the UI for the OTP
            var otp = ui.ProvideSecondFactorPassword(otpChannel);

            // Step 3: Send the OTP.
            var shouldBeSession = PerformScramSequence(credentials, new OtpOptions(otpChannel, otp.Password, otp.RememberDevice), rest);

            // We should be really logged in this time.
            if (shouldBeSession.Session != null)
                return shouldBeSession.Session;

            throw new BadMultiFactorException("Invalid second factor code");
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

        internal static ScramResult PerformScramSequence(Credentials credentials, OtpOptions otp, RestClient rest)
        {
            // TODO: Shouldn't Step1 return AuthInfo and not a header?
            var header = Step1(credentials, otp, rest);
            var authInfo = AuthInfo.Parse(header);
            return Step2(credentials, otp, authInfo, rest);
        }

        internal static void Logout(Session session, RestClient rest)
        {
            var response = rest.PostForm("?logout", new Dictionary<string, object>(), cookies: session.Cookies);
            // TODO: Do we want to abort on the failed logout? If we got here it means we
            //       have a parsed vault and aborting at this stage is gonna prevent the
            //       user from getting it. On the other hand this will help to catch
            //       any bugs in the logout code if the protocol changes. It's important
            //       to log out as the server usually keeps track of open sessions and
            //       might start blocking new sessions at some point.
            if (!response.IsSuccessful)
                throw MakeError(response);
        }

        internal static (List<Account> Accounts, RSAParameters? PrivateKey) OpenFolder(
            Session session,
            string password,
            string parentPath,
            RestClient rest
        )
        {
            var blob = GetBlob(session, rest);
            var json = OneFile.Parse(blob, password);
            return VaultParser.Parse(json, parentPath);
        }

        internal static List<Account> OpenSharedFolder(R.SharedFolderInfo info, Session session, RSAParameters privateKey, IRestTransport transport)
        {
            if (!info.Accepted)
                return new List<Account>(0);

            var encryptedKey = info.EncryptedKey ?? "";
            if (encryptedKey.IsNullOrEmpty())
                return new List<Account>(0);

            var password = Crypto.DecryptRsaPkcs1(encryptedKey.Decode64(), privateKey).ToUtf8();

            // Each shared folder is like an independent vault with its own password
            return OpenFolder(session, password, info.Name ?? "-", new RestClient(transport, ApiBaseUrl(info.Id))).Accounts;
        }

        internal static byte[] GetBlob(Session session, RestClient rest)
        {
            var response = rest.GetBinary("user-data.rfo", cookies: session.Cookies);
            if (!response.IsSuccessful)
                throw MakeError(response);

            return response.Content;
        }

        internal static R.SharedFolderInfo[] GetSharedFolderList(Session session, RestClient rest)
        {
            var response = rest.Get<R.ReceivedItems>("?received", cookies: session.Cookies);
            if (!response.IsSuccessful)
                throw MakeError(response);

            return response.Data.SharedFolders;
        }

        internal static Dictionary<string, string> ScramHeaders(string authorization, OtpOptions otp)
        {
            var headers = new Dictionary<string, string> { ["Authorization"] = authorization, ["x-sib-auth-alt-channel"] = otp.Channel ?? "-" };

            if (otp.Password != null)
            {
                headers["x-sib-auth-alt-otp"] = otp.Password;
                headers["x-sib-auth-alt-memorize"] = otp.RememberMe ? "1" : "0";
            }

            return headers;
        }

        internal static Dictionary<string, string> ScramCookies(string deviceId)
        {
            return new Dictionary<string, string> { ["sib-deviceid"] = deviceId };
        }

        internal static string Step1(Credentials credentials, OtpOptions otp, RestClient rest)
        {
            var response = rest.PostForm(
                "?login",
                new Dictionary<string, object>(),
                ScramHeaders(Step1AuthorizationHeader(credentials), otp),
                ScramCookies(credentials.DeviceId)
            );

            // First check for any errors that might have happened during the request
            if (response.HasError)
                throw MakeError(response);

            // 401 is expected as the only valid response at this point
            if (response.StatusCode != HttpStatusCode.Unauthorized)
                throw new InternalErrorException($"Unauthorized (401) is expected in the response, got {(int)response.StatusCode} instead");

            // WWW-Authenticate has the result of this step.
            var header = response.Headers.GetOrDefault("WWW-Authenticate", "");
            if (header.IsNullOrEmpty())
                throw new InternalErrorException("WWW-Authenticate header is not found in the response");

            return header;
        }

        internal static ScramResult Step2(Credentials credentials, OtpOptions otp, AuthInfo authInfo, RestClient rest)
        {
            var response = rest.PostForm(
                "?login",
                new Dictionary<string, object>(),
                ScramHeaders(Step2AuthorizationHeader(credentials, authInfo), otp),
                ScramCookies(credentials.DeviceId)
            );

            // First check for any errors that might have happened during the request
            if (response.HasError)
                throw MakeError(response);

            // Step2 fails with 401 on incorrect username, password or OTP
            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                var requestedOtpChannel = response.Headers.GetOrDefault("x-sib-auth-alt-otp", "");
                if (!requestedOtpChannel.IsNullOrEmpty())
                    return new ScramResult(requestedOtpChannel);

                // If OTP is set then it's the OTP that is wrong
                if (otp.Password != null)
                    throw new BadMultiFactorException("Invalid second factor code");

                throw new BadCredentialsException("Invalid username or password");
            }

            // Otherwise step2 is supposed to succeed
            if (!response.IsSuccessful)
                throw MakeError(response);

            var auth = response.Cookies.GetOrDefault("sib-auth", "");
            if (auth.IsNullOrEmpty())
                throw new InternalErrorException("'sib-auth' cookie wasn't found in the response");

            var device = response.Cookies.GetOrDefault("sib-deviceid", "");
            if (device.IsNullOrEmpty())
                throw new InternalErrorException("'sib-deviceid' cookie wasn't found in the response");

            return new ScramResult(new Session(auth, device));
        }

        internal static string GenerateNonce()
        {
            return Crypto.RandomBytes(16).ToUrlSafeBase64NoPadding();
        }

        internal static string Step1AuthorizationHeader(Credentials credentials)
        {
            var data = string.Format("n,,n={0},r={1}", credentials.Username.EncodeUri(), credentials.Nonce).ToBase64();
            return $"SibAuth realm=\"RoboForm Online Server\",data=\"{data}\"";
        }

        internal static string Step2AuthorizationHeader(Credentials credentials, AuthInfo authInfo)
        {
            var clientKey = Util.ComputeClientKey(credentials.Password, authInfo);
            var clientHash = Crypto.Sha256(clientKey);

            var hashingMaterial = string.Format(
                "n={0},r={1},{2},c=biws,r={3}",
                credentials.Username.EncodeUri(),
                credentials.Nonce,
                authInfo.Data,
                authInfo.Nonce
            );

            var hashed = Crypto.HmacSha256(clientHash, hashingMaterial.ToBytes());
            var proof = clientKey.Zip(hashed, (a, b) => (byte)(a ^ b)).ToArray().ToBase64();
            var data = $"c=biws,r={authInfo.Nonce},p={proof}".ToBase64();

            return $"SibAuth sid=\"{authInfo.Sid}\",data=\"{data}\"";
        }

        internal static string ApiBaseUrl(string username)
        {
            var uriEncodedUsername = username.EncodeUri();
            return $"https://online.roboform.com/rf-api/{uriEncodedUsername}";
        }

        //
        // Private
        //

        private static BaseException MakeError(RestResponse response)
        {
            var failedWith = $"Request to {response.RequestUri} failed with";

            if (response.IsNetworkError)
                return new NetworkErrorException($"{failedWith} a network error", response.Error);

            if (response.Error is JsonException)
                return new InternalErrorException($"{failedWith} JSON deserialization error", response.Error);

            if (response.IsHttpError)
                return new InternalErrorException($"{failedWith} HTTP status {(int)response.StatusCode}");

            return new InternalErrorException($"{failedWith} an unknown error", response.Error);
        }
    }
}
