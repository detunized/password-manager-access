// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Specialized;
using System.Net;
using System.Text.RegularExpressions;
using Newtonsoft.Json.Linq;

namespace ZohoVault
{
    public static class Remote
    {
        private const string LoginUrl =
            "https://accounts.zoho.com/login?scopes=ZohoVault/vaultapi,ZohoContacts/photoapi&appname=zohovault/2.5.1&serviceurl=https://vault.zoho.com&hide_remember=true&hide_logo=true&hidegooglesignin=false&hide_signup=false";

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
            var response = webClient.UploadValues(LoginUrl, new NameValueCollection
            {
                {"LOGIN_ID", username},
                {"PASSWORD", password},
                {"IS_AJAX", "true"},
                {"remember", "-1"},
                {"hide_reg_link", "false"},
                {"iamcsrcoo", iamcsrcoo}
            });

            // TODO: Handle errors

            // The returned text is JavaScript which is supposed to call some functions on the
            // original page. "showsuccess" is called when everything went well.
            var responseText = response.ToUtf8();
            if (!responseText.StartsWith("showsuccess"))
                // TODO: Use custom exception
                throw new InvalidOperationException("Login failed, credentials are invalid");

            // Extract the token from the response headers
            var cookies = webClient.ResponseHeaders[HttpResponseHeader.SetCookie];
            var match = Regex.Match(cookies, "\\bIAMAUTHTOKEN=(\\w+);");
            if (!match.Success)
                // TODO: Use custom exception
                throw new InvalidOperationException("Unsupported cookie format");

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

        internal struct AuthInfo
        {
            public AuthInfo(int iterationCount, byte[] salt, byte[] encryptedPassphrase)
            {
                IterationCount = iterationCount;
                Salt = salt;
                EncryptedPassphrase = encryptedPassphrase;
            }

            public int IterationCount;
            public byte[] Salt;
            public byte[] EncryptedPassphrase;
        }

        internal static AuthInfo GetAuthInfo(string token, IWebClient client)
        {
            // Set headers
            client.Headers[HttpRequestHeader.Authorization] = string.Format("Zoho-authtoken {0}", token);
            client.Headers[HttpRequestHeader.UserAgent] = "ZohoVault/2.5.1 (Android 4.4.4; LGE/Nexus 5/19/2.5.1";
            client.Headers["requestFrom"] = "vaultmobilenative";

            // GET
            var response = client.DownloadData("https://vault.zoho.com/api/json/login?OPERATION_NAME=GET_LOGIN");

            // Parse the response
            var parsed = JObject.Parse(response.ToUtf8());
            if (parsed.StringAt("operation/result/status") != "success")
                throw new InvalidOperationException("Invalid response");

            // Validate the response
            var details = parsed.At("operation/details");
            if (details.StringAt("LOGIN") != "PBKDF2_AES")
                throw new InvalidOperationException("Only PBKDF2/AES is supported");

            // Extract and convert important information
            return new AuthInfo(
                details.IntAt("ITERATION"),
                details.StringAt("SALT").ToBytes(),
                details.StringAt("PASSPHRASE").ToBytes() // TODO: Decode base64 here
            );
        }
    }
}
