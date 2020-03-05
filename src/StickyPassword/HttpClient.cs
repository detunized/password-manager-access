// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;

namespace PasswordManagerAccess.StickyPassword
{
    // TODO: Would be good to have some tests for this implementation.
    //       WebRequest.Create would have to be replaced with some factory first.
    internal class HttpClient: IHttpClient
    {
        public const string DefaultBaseUrl = "https://spcb.stickypassword.com/SPCClient/";

        public HttpClient(string baseUrl = DefaultBaseUrl)
        {
            _baseUrl = baseUrl;
        }

        public string Post(string endpoint,
                           string userAgent,
                           DateTime timestamp,
                           Dictionary<string, string> parameters)
        {
            return Post(endpoint, userAgent, "", timestamp, parameters);
        }

        public string Post(string endpoint,
                           string userAgent,
                           string authorization,
                           DateTime timestamp,
                           Dictionary<string, string> parameters)
        {
            var request = (HttpWebRequest)WebRequest.Create(_baseUrl + endpoint);
            request.Method = "POST";
            request.ContentType = "application/x-www-form-urlencoded; charset=UTF-8";
            request.Accept = "application/xml";
            request.Date = timestamp;
            request.UserAgent = userAgent;

            if (!string.IsNullOrEmpty(authorization))
                request.Headers["Authorization"] = authorization;

            var content = string.Join("&", parameters.Select(
                i => string.Format(
                    CultureInfo.InvariantCulture,
                    "{0}={1}",
                    Uri.EscapeDataString(i.Key),
                    Uri.EscapeDataString(i.Value)))).ToBytes();

            using (var stream = request.GetRequestStream())
                stream.Write(content, 0, content.Length);

            using (var response = (HttpWebResponse)request.GetResponse())
            using (var reader = new StreamReader(response.GetResponseStream()))
                return reader.ReadToEnd();
        }

        private readonly string _baseUrl;
    }
}
