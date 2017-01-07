// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using RestSharp;

namespace StickyPassword
{
    public static class Remote
    {
        private const string ApiUrl = "https://spcb.stickypassword.com/SPCClient/";

        public static string GetEncryptedToken(string username, string deviceId)
        {
            var response = Post("GetCrpToken", deviceId, DateTime.Now, new Dictionary<string, string>()
            {
                {"uaid", username},
            });

            // TODO: Parse the response
            return response.Content;
        }

        private static string GetUserAgent(string deviceId)
        {
            return string.Format("SP/8.0.3436 Prot=2 ID={0} Lng=EN Os=Android/4.4.4 Lic= LicStat= PackageID=", deviceId);
        }

        private static RestClient CreateClient(string deviceId)
        {
            return new RestClient(ApiUrl)
            {
                UserAgent = GetUserAgent(deviceId)
            };
        }

        private static IRestResponse Post(string endPoint, string deviceId, DateTime timestamp,
            Dictionary<string, string> parameters)
        {
            var client = CreateClient(deviceId);

            var request = new RestRequest(endPoint, Method.POST);
            SetRequestHeaders(request, timestamp);

            foreach (var i in parameters)
                request.AddParameter(i.Key, i.Value);

            return client.Execute(request);
        }

        private static void SetRequestHeaders(RestRequest request, DateTime timestamp)
        {
            request.AddHeader("Date", timestamp.ToUniversalTime().ToString("R"));
            request.AddHeader("Accept", "application/xml");
        }
    }
}
