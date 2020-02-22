// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using SystemHttp = System.Net.Http.HttpClient;

namespace PasswordManagerAccess.RoboForm
{
    // TODO: Reuse HttpClient, it's not supposed to be instantiated for every request.
    // See https://docs.microsoft.com/en-us/dotnet/api/system.net.http.httpclient?view=netframework-4.5

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

        public HttpResponseMessage Get(string url, Dictionary<string, string> headers)
        {
            using (var http = CreateHttp(headers))
                return http.GetAsync(url).Result;
        }

        public HttpResponseMessage Post(string url, Dictionary<string, string> headers)
        {
            using (var http = CreateHttp(headers))
                return http.PostAsync(url, new StringContent("")).Result;
        }

        //
        // Private
        //

        private static SystemHttp CreateHttp(Dictionary<string, string> headers)
        {
            var http = new SystemHttp(new HttpClientHandler {UseCookies = false});
            foreach (var i in headers)
                http.DefaultRequestHeaders.Add(i.Key, i.Value);

            return http;
        }
    }
}
