// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;

namespace RoboForm
{
    internal static class Client
    {
        public static Vault OpenVault(string username, string password, IHttpClient http)
        {
            var session = Login(username, password, http);
            try
            {
                var blob = GetBlob(username, session, http);
                var json = OneFile.Parse(blob, password);
                return VaultParser.Parse(json);
            }
            finally
            {
                Logout(username, session, http);
            }
        }

        //
        // Internal
        //

        internal static Session Login(string username, string password, IHttpClient http)
        {
            return Login(username, password, GenerateNonce(), http);
        }

        internal static Session Login(string username, string password, string nonce, IHttpClient http)
        {
            var header = Step1(username, nonce, http);
            var authInfo = AuthInfo.Parse(header);
            var session = Step2(username, password, nonce, authInfo, http);

            return session;
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
            // TODO: Make this random
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

        internal static string Step1(string username, string nonce, IHttpClient http)
        {
            // TODO: Wrap in using when done
            var response = http.Post(LoginUrl(username), new Dictionary<string, string>
            {
                {"Authorization", Step1AuthorizationHeader(username, nonce)}
            });

            // Handle this separately not to have a confusing error message on "success"
            if (response.IsSuccessStatusCode)
                throw MakeInvalidResponse(
                    string.Format(
                        "Unauthorized (401) is expected in the response, got {0} ({1}) instead",
                        response.StatusCode,
                        (int)response.StatusCode));

            if (response.StatusCode != HttpStatusCode.Unauthorized)
                throw MakeNetworkError(response.StatusCode);

            var header = GetHeader(response, "WWW-Authenticate");
            if (string.IsNullOrWhiteSpace(header))
                throw MakeInvalidResponse("WWW-Authenticate header wasn't found in the response");

            return header;
        }

        internal static Session Step2(string username,
                                      string password,
                                      string nonce,
                                      AuthInfo authInfo,
                                      IHttpClient http)
        {
            var response = http.Post(LoginUrl(username), new Dictionary<string, string>
            {
                {"Authorization", Step2AuthorizationHeader(username, password, nonce, authInfo)}
            });

            // Step2 fails with 401 on incorrect username or password
            if (response.StatusCode == HttpStatusCode.Unauthorized)
                throw new ClientException(ClientException.FailureReason.IncorrectCredentials,
                                          "Username or password is incorrect");

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

            return new Session(auth.Value, device.Value);
        }

        internal static string GenerateNonce()
        {
            return Crypto.RandomBytes(16).ToUrlSafeBase64();
        }

        internal static string Step1AuthorizationHeader(string username, string nonce)
        {
            var data = string.Format("n,,n={0},r={1}", username.EncodeUri(), nonce);
            return string.Format("SibAuth realm=\"RoboForm Online Server\",data=\"{0}\"",
                                 data.ToBase64());
        }

        internal static string Step2AuthorizationHeader(string username,
                                                        string password,
                                                        string nonce,
                                                        AuthInfo authInfo)
        {
            var clientKey = Crypto.ComputeClientKey(password, authInfo);
            var clientHash = Crypto.Sha256(clientKey);

            var hashingMaterial = string.Format("n={0},r={1},{2},c=biws,r={3}",
                                                username.EncodeUri(),
                                                nonce,
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
