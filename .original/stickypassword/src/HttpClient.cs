// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Web;

namespace StickyPassword
{
    // TODO: Would be good to have some tests for this implementation.
    //       WebRequest.Create would have to be replaced with some factory first.
    public class HttpClient: IHttpClient
    {
        public string Post(string url,
                           string userAgent,
                           DateTime timestamp,
                           Dictionary<string, string> parameters)
        {
            return Post(url, userAgent, "", timestamp, parameters);
        }

        public string Post(string url,
                           string userAgent,
                           string authorization,
                           DateTime timestamp,
                           Dictionary<string, string> parameters)
        {
            var request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = "POST";
            request.ContentType = "application/x-www-form-urlencoded; charset=UTF-8";
            request.Accept = "application/xml";
            request.Date = timestamp;
            request.UserAgent = userAgent;

            if (!string.IsNullOrEmpty(authorization))
                request.Headers["Authorization"] = authorization;

            var content = string.Join("&", parameters.Select(
                i => string.Format(
                    "{0}={1}",
                    HttpUtility.UrlEncode(i.Key),
                    HttpUtility.UrlEncode(i.Value)))).ToBytes();

            using (var stream = request.GetRequestStream())
                stream.Write(content, 0, content.Length);

            using (var response = (HttpWebResponse)request.GetResponse())
            using (var reader = new StreamReader(response.GetResponseStream()))
                return reader.ReadToEnd();
        }
    }
}
