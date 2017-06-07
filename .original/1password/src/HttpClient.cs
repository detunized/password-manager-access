// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Net;

namespace OnePassword
{
    public class HttpClient: IHttpClient
    {
        public string Get(string url, Dictionary<string, string> headers)
        {
            using (var client = new WebClient())
            {
                foreach (var i in headers)
                    client.Headers[i.Key] = i.Value;

                return client.DownloadString(url);
            }
        }

        public string Post(string url, string content, Dictionary<string, string> headers)
        {
            using (var client = new WebClient())
            {
                foreach (var header in headers)
                    client.Headers[header.Key] = header.Value;

                return client.UploadString(url, content);
            }
        }
    }
}
