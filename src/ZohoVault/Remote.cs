// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Specialized;
using System.Net;
using System.Text.RegularExpressions;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.ZohoVault
{
    public static class Remote
    {
        private const string LoginUrl =
            "https://accounts.zoho.com/login?scopes=ZohoVault/vaultapi,ZohoContacts/photoapi&appname=zohovault/2.5.1&serviceurl=https://vault.zoho.com&hide_remember=true&hide_logo=true&hidegooglesignin=false&hide_signup=false";
        private const string LogoutUrl = "https://accounts.zoho.com/apiauthtoken/delete";
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

            // Set a cookie with some random gibberish
            webClient.Headers.Add(HttpRequestHeader.Cookie, string.Format("iamcsr={0}", iamcsrcoo));

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
                throw new BadCredentialsException("Login failed, most likely the credentials are invalid");

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
            var url = string.Format("{0}?AUTHTOKEN={1}", LogoutUrl, token);
            Get(url, token, webClient);
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
                throw new BadCredentialsException("Passphrase is incorrect");

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

        internal static string Get(string url, string token, IWebClient webClient)
        {
            // Set headers
            webClient.Headers[HttpRequestHeader.Authorization] = string.Format("Zoho-authtoken {0}", token);
            webClient.Headers[HttpRequestHeader.UserAgent] = "ZohoVault/2.5.1 (Android 4.4.4; LGE/Nexus 5/19/2.5.1";
            webClient.Headers["requestFrom"] = "vaultmobilenative";

            try
            {
                // GET
                return webClient.DownloadData(url).ToUtf8();
            }
            catch (WebException e)
            {
                throw MakeNetworkError(e);
            }
        }

        internal static JToken GetJsonObject(string url, string token, IWebClient webClient)
        {
            JObject parsed;
            try
            {
                parsed = JObject.Parse(Get(url, token, webClient));
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

        private static NetworkErrorException MakeNetworkError(WebException original)
        {
            return new NetworkErrorException("Network error occurred", original);
        }

        private static InternalErrorException MakeInvalidResponseFormat()
        {
            return MakeInvalidResponse("Invalid response format");
        }

        private static InternalErrorException MakeInvalidResponse(string message, Exception original = null)
        {
            return new InternalErrorException(message, original);
        }
    }
}
