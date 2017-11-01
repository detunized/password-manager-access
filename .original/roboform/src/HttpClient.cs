// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Net;

namespace RoboForm
{
    public class HttpClient: IHttpClient
    {
        public byte[] Get(string url, Dictionary<string, string> headers)
        {
            using (var client = new WebClient())
                return SetHeaders(client, headers).DownloadData(url);
        }

        public byte[] Post(string url, Dictionary<string, string> headers)
        {
            using (var client = new WebClient())
                return SetHeaders(client, headers).UploadData(url, new byte[] {});
        }

        //
        // Private
        //

        private static WebClient SetHeaders(WebClient client, Dictionary<string, string> headers)
        {
            foreach (var i in headers)
                client.Headers[i.Key] = i.Value;

            return client;
        }
    }
}
