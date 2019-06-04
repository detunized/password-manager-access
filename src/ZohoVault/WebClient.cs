// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using RestSharp;

namespace PasswordManagerAccess.ZohoVault
{
    class WebClient: IWebClient, IDisposable
    {
        public IRestResponse Get(string url, Dictionary<string, string> headers, Dictionary<string, string> cookies)
        {
            return _restClient.Get(MakeRequest(url, headers, cookies));
        }

        public IRestResponse<T> Get<T>(string url,
                                       Dictionary<string, string> headers,
                                       Dictionary<string, string> cookies) where T: new()
        {
            return _restClient.Get<T>(MakeRequest(url, headers, cookies));
        }

        public IRestResponse Post(string url,
                                  Dictionary<string, object> parameters,
                                  Dictionary<string, string> headers,
                                  Dictionary<string, string> cookies)
        {
            var request = MakeRequest(url, headers, cookies);

            // Add POST parameters
            foreach (var p in parameters)
                request.AddParameter(p.Key, p.Value.ToString());

            return _restClient.Post(request);
        }

        //
        // IDisposable
        //

        public void Dispose()
        {
            // Currently there's nothing to dispose of
        }

        //
        // Private
        //

        private RestRequest MakeRequest(string url, Dictionary<string, string> headers, Dictionary<string, string> cookies)
        {
            var request = new RestRequest(url);

            if (headers != null)
                foreach (var h in headers)
                    request.AddHeader(h.Key, h.Value);

            if (cookies != null)
                foreach (var c in cookies)
                    request.AddCookie(c.Key, c.Value);

            return request;
        }

        private RestClient _restClient = new RestClient();
    }
}
