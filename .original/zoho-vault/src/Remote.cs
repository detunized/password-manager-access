// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Specialized;
using System.Net;
using System.Text.RegularExpressions;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace ZohoVault
{
    public static class Remote
    {
        private const string LoginUrl =
            "https://accounts.zoho.com/login?scopes=ZohoVault/vaultapi,ZohoContacts/photoapi&appname=zohovault/2.5.1&serviceurl=https://vault.zoho.com&hide_remember=true&hide_logo=true&hidegooglesignin=false&hide_signup=false";
        private const string AuthUrl =
            "https://vault.zoho.com/api/json/login?OPERATION_NAME=GET_LOGIN";
        private const string VaultUrl =
            "https://vault.zoho.com/api/json/login?OPERATION_NAME=OPEN_VAULT&limit=200";

        public static string Login(string username, string password)
        {
            using (var webClient = new WebClient())
                return Login(username, password, webClient);
        }

        public static string Login(string username, string password, IWebClient webClient)
        {
            // TODO: This should probably be random
            const string iamcsrcoo = "12345678-1234-1234-1234-1234567890ab";

            // TODO: This should be new every time or should be requested from the server
            //       otherwise it seems that the server assigns it under SESSIONID=""
            //       and at some point it runs out of tokens for this session.
            // TODO: Figure out a way to test it with a random session id
            const string sessionId = "27AAFCA1DC962FEA2FC1E53D5749CF1B";

            // TODO: It looks like this doesn't help very much. We should request a page from
            // https://accounts.zoho.com/login?scopes=ZohoVault/vaultapi,ZohoContacts/photoapi&appname=zohovault/2.5.1&serviceurl=https://vault.zoho.com&hide_remember=true&hide_logo=true&hidegooglesignin=false&hide_signup=false
            // (see android2.flow in zoho repo). Extract iamcsr, JSESSIONID and maybe other cookies
            // to request the login.

            // Set a cookie with some random gibberish
            webClient.Headers.Add(HttpRequestHeader.Cookie,
                string.Format("iamcsr={0};JSESSIONID={1}", iamcsrcoo, sessionId));

            // POST
            byte[] response;
            try
            {
                response = webClient.UploadValues(LoginUrl, new NameValueCollection
                {
                    {"LOGIN_ID", username},
                    {"PASSWORD", password},
                    {"IS_AJAX", "true"},
                    {"remember", "-1"},
                    {"hide_reg_link", "false"},
                    {"iamcsrcoo", iamcsrcoo}
                });
            }
            catch (WebException e)
            {
                throw MakeNetworkError(e);
            }

            // The returned text is JavaScript which is supposed to call some functions on the
            // original page. "showsuccess" is called when everything went well.
            var responseText = response.ToUtf8();
            if (!responseText.StartsWith("showsuccess"))
                throw new FetchException(FetchException.FailureReason.InvalidCredentials, "Login failed, most likely the credentials are invalid");

            // Extract the token from the response headers
            var cookies = webClient.ResponseHeaders[HttpResponseHeader.SetCookie];
            var match = Regex.Match(cookies, "\\bIAMAUTHTOKEN=(\\w+);");
            if (!match.Success)
                throw MakeInvalidResponse("Unsupported cookie format");

            return match.Groups[1].Value;
        }

        public static void Logout(string token)
        {
            using (var webClient = new WebClient())
                Logout(token, webClient);
        }

        public static void Logout(string token, IWebClient webClient)
        {
            throw new NotImplementedException();
        }

        // TODO: Rather return a session object or something like that
        // Returns the encryption key
        public static byte[] Authenticate(string token, string passphrase, IWebClient webClient)
        {
            // Fetch key derivation parameters and some other stuff
            var info = GetAuthInfo(token, webClient);

            // Decryption key
            var key = Crypto.ComputeKey(passphrase, info.Salt, info.IterationCount);

            // Verify that the key is correct
            // AuthInfo.EncryptionCheck contains some encrypted JSON that could be
            // decrypted and parsed to check if the passphrase is correct. We have
            // to rely here on the encrypted JSON simply not parsing correctly and
            // producing some sort of error.
            var decrypted = Crypto.Decrypt(info.EncryptionCheck, key).ToUtf8();

            // TODO: See if ToUtf8 could throw something

            JToken parsed = null;
            try
            {
                parsed = JToken.Parse(decrypted);
            }
            catch (JsonException)
            {
            }

            // This would be null in case of JSON exception or if Parse returned null (would it?)
            if (parsed == null)
                throw new FetchException(FetchException.FailureReason.InvalidPassphrase, "Passphrase is incorrect");

            return key;
        }

        public static JToken DownloadVault(string token, byte[] key, IWebClient webClient)
        {
            return GetJsonObject(VaultUrl, token, webClient);
        }

        internal struct AuthInfo
        {
            public AuthInfo(int iterationCount, byte[] salt, byte[] encryptionCheck)
            {
                IterationCount = iterationCount;
                Salt = salt;
                EncryptionCheck = encryptionCheck;
            }

            public int IterationCount;
            public byte[] Salt;
            public byte[] EncryptionCheck;
        }

        internal static AuthInfo GetAuthInfo(string token, IWebClient webClient)
        {
            var response = GetJsonObject(AuthUrl, token, webClient);

            if (response.StringAtOrNull("LOGIN") != "PBKDF2_AES")
                throw MakeInvalidResponse("Only PBKDF2/AES is supported");

            // Extract and convert important information
            var iterations = response.IntAtOrNull("ITERATION");
            var salt = response.StringAtOrNull("SALT");
            var passphrase = response.StringAtOrNull("PASSPHRASE");

            if (iterations == null || salt == null || passphrase == null)
                throw MakeInvalidResponseFormat();

            return new AuthInfo(iterations.Value, salt.ToBytes(), passphrase.Decode64());
        }

        internal static JToken GetJsonObject(string url, string token, IWebClient webClient)
        {
            // Set headers
            webClient.Headers[HttpRequestHeader.Authorization] = string.Format("Zoho-authtoken {0}", token);
            webClient.Headers[HttpRequestHeader.UserAgent] = "ZohoVault/2.5.1 (Android 4.4.4; LGE/Nexus 5/19/2.5.1";
            webClient.Headers["requestFrom"] = "vaultmobilenative";

            JObject parsed;
            try
            {
                // GET
                var response = webClient.DownloadData(url);

                // Parse
                parsed = JObject.Parse(response.ToUtf8());
            }
            catch (WebException e)
            {
                throw MakeNetworkError(e);
            }
            catch (JsonException e)
            {
                throw MakeInvalidResponse("Invalid JSON in response", e);
            }

            if (parsed.StringAtOrNull("operation/result/status") != "success")
                throw MakeInvalidResponseFormat();

            var details = parsed.AtOrNull("operation/details");
            if (details == null || details.Type != JTokenType.Object)
                throw MakeInvalidResponseFormat();

            return details;
        }

        private static FetchException MakeNetworkError(WebException innerException)
        {
            return new FetchException(FetchException.FailureReason.NetworkError, "Network error occurred", innerException);
        }

        private static FetchException MakeInvalidResponseFormat()
        {
            return MakeInvalidResponse("Invalid response format");
        }

        private static FetchException MakeInvalidResponse(string message, Exception innerException = null)
        {
            return new FetchException(FetchException.FailureReason.InvalidResponse, message, innerException);
        }
    }
}
