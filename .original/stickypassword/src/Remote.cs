// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Specialized;
using System.Net;
using System.Text;

namespace StickyPassword
{
    public static class Remote
    {
        private const string ApiUrl = "https://spcb.stickypassword.com/SPCClient";
        private const string TokenUrl = ApiUrl + "/GetCrpToken";

        public static string GetEncryptedToken(string username, string deviceId, IWebClient webClient)
        {
            SetRequestHeaders(webClient.Headers, deviceId, DateTime.Now);

            // TODO: Handle network errors
            var response = webClient.UploadValues(TokenUrl, new NameValueCollection
            {
                {"uaid", username},
            });

            // TODO: Parse JSON
            return Encoding.UTF8.GetString(response);
        }

        private static void SetRequestHeaders(WebHeaderCollection headers, string deviceId, DateTime timestamp)
        {
            headers.Set("User-Agent",
                string.Format("SP/8.0.3436 Prot=2 ID=#{0} Lng=EN Os=Android/4.4.4 Lic= LicStat= PackageID=", deviceId));
            headers.Set("Date", timestamp.ToUniversalTime().ToString("r"));
            headers.Set("Accept", "application/xml");
            headers.Set("Pragma", "no-cache");
            headers.Set("Cache-Control", "no-cache");
            headers.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
            headers.Set("host", "spcb.stickypassword.com");
            headers.Set("Connection", "Keep-Alive");
            headers.Set("Accept-Encoding", "gzip");
        }
    }
}
