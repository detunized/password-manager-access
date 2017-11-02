// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Net;

namespace RoboForm
{
    public static class Client
    {
        public static void Login(string username, string password, IHttpClient http)
        {
            Step1(username, "-DeHRrZjC8DZ_0e8RGsisg", http);
        }

        internal static void Step1(string username, string nonce, IHttpClient http)
        {
            var responose = http.Post(LoginUrl(username), new Dictionary<string, string>
            {
                {"Authorization", Step1AuthorizationHeader(username, nonce)}
            });

            if (responose.StatusCode != HttpStatusCode.Unauthorized)
                throw new InvalidOperationException("Expected 401"); // TODO: Custom exception
        }

        internal static string Step1AuthorizationHeader(string username, string nonce)
        {
            var data = string.Format("n,,n={0},r={1}", username.EncodeUri(), nonce);
            return string.Format("SibAuth realm=\"RoboForm Online Server\",data=\"{0}\"",
                                 data.ToBase64());
        }

        internal static string LoginUrl(string username)
        {
            return string.Format("https://online.roboform.com/rf-api/{0}?login",
                                 username.EncodeUri());
        }
    }
}
