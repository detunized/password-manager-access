// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;

namespace RoboForm
{
    public static class Client
    {
        public static void Login(string username, string password, IHttpClient http)
        {
            Step1(username, "-DeHRrZjC8DZ_0e8RGsisg", http);
        }

        private static void Step1(string username, string nonce, IHttpClient http)
        {
            http.Post(LoginUrl(username), new Dictionary<string, string>
            {
                {"Authorization", Step1AuthorizationHeader(username, nonce)}
            });
        }

        private static string Step1AuthorizationHeader(string username, string nonce)
        {
            return string.Format("TODO: {0} {1}", username, nonce);
        }

        private static string LoginUrl(string username)
        {
            return string.Format("https://online.roboform.com/rf-api/{0}?login", username);
        }
    }
}
