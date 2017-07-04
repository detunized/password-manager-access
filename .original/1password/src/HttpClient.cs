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
                return SetHeaders(client, headers).DownloadString(url);
        }

        public string Post(string url, string content, Dictionary<string, string> headers)
        {
            return UploadString(url, "POST", content, headers);
        }

        public string Put(string url, Dictionary<string, string> headers)
        {
            return UploadString(url, "PUT", "", headers);
        }

        //
        // Private
        //

        private static string UploadString(string url,
                                           string method,
                                           string content,
                                           Dictionary<string, string> headers)
        {
            using (var client = new WebClient())
                return SetHeaders(client, headers).UploadString(url, method, content);
        }

        private static WebClient SetHeaders(WebClient client, Dictionary<string, string> headers)
        {
            foreach (var i in headers)
                client.Headers[i.Key] = i.Value;

            return client;
        }
    }
}
