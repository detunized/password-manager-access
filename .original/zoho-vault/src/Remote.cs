// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Specialized;
using System.Net;
using System.Text.RegularExpressions;

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
            throw new NotImplementedException();
        }
    }
}
