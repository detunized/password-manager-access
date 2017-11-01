// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Net.Http;
using SystemHttp = System.Net.Http.HttpClient;

namespace RoboForm
{
    // TODO: Reuse HttpClient, it's not supposed to be instantiated for every request.
    // See https://docs.microsoft.com/en-us/dotnet/api/system.net.http.httpclient?view=netframework-4.5

    public class HttpClient: IHttpClient
    {
        public HttpResponseMessage Get(string url, Dictionary<string, string> headers)
        {
            using (var http = new SystemHttp())
                return SetHeaders(http, headers).GetAsync(url).Result;
        }

        public HttpResponseMessage Post(string url, Dictionary<string, string> headers)
        {
            using (var http = new SystemHttp())
                return SetHeaders(http, headers).PostAsync(url, new StringContent("")).Result;
        }

        //
        // Private
        //

        private static SystemHttp SetHeaders(SystemHttp client, Dictionary<string, string> headers)
        {
            foreach (var i in headers)
                client.DefaultRequestHeaders.Add(i.Key, i.Value);

            return client;
        }
    }
}
