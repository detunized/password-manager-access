// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Net;

namespace PasswordManagerAccess.Common
{
    internal sealed class HttpClient: IHttpClient
    {
        public string Get(string url, Dictionary<string, string> headers)
        {
            using (var client = NewWebClient())
                return SetHeaders(client, headers).DownloadString(url);
        }

        public string Post(string url, string content, Dictionary<string, string> headers)
        {
            using (var client = NewWebClient())
                return SetHeaders(client, headers).UploadString(url, content);
        }

        //
        // Protected
        //

        private static WebClient NewWebClient()
        {
            return new WebClient();
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
