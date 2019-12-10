// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Net;

namespace OnePassword
{
    public class HttpClient: IHttpClient
    {
        static HttpClient()
        {
            // This enables TLS 1.2 amongst other things. Without this .NET 4.0 or 4.5 fails to
            // connect to 1password.com. This should be not needed with .NET 4.6. For TLS 1.1 and 1.2
            // we have to use the numerical values for .NET 4.0. Strangely they work, thought
            // actual constants are only defined in .NET 4.5.
            // see https://stackoverflow.com/a/40295737/362938
            // see http://blogs.perficient.com/microsoft/2016/04/tsl-1-2-and-net-support/
            //
            // Warning: This is global (or app domain level) so it could mess up some things for
            //          the application that uses the library!
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Ssl3 |
                                                   SecurityProtocolType.Tls |
                                                   (SecurityProtocolType)768 | // Tls11, enum is defined in 4.5
                                                   (SecurityProtocolType)3072; // Tls12, enum is defined in 4.5
        }

        public string Get(string url, Dictionary<string, string> headers)
        {
            using (var client = NewWebClient())
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
        // Protected
        //

        protected virtual WebClient NewWebClient()
        {
            return new WebClient();
        }

        //
        // Private
        //

        private string UploadString(string url,
                                    string method,
                                    string content,
                                    Dictionary<string, string> headers)
        {
            using (var client = NewWebClient())
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
