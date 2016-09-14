// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Specialized;
using System.Net;
using System.Text;
using Newtonsoft.Json;
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

            // TODO: Set a cookie
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

            var responseText = Encoding.UTF8.GetString(response);
            if (!responseText.StartsWith("showsuccess"))
                throw new InvalidOperationException("Login failed, credentials are invalid");

            // TODO: Get token out of the response headers
            return "<token>";
        }
    }
}
