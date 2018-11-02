// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Net;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Bitwarden
{
    internal class JsonHttpClient
    {
        public JsonHttpClient(IHttpClient http, string baseUrl)
        {
            Http = http;
            BaseUrl = baseUrl.TrimEnd('/');
            Headers = new Dictionary<string, string>();
        }

        public IHttpClient Http { get; private set; }
        public string BaseUrl { get; private set; }
        public Dictionary<string, string> Headers { get; set; }

        //
        // Get
        //

        public JObject Get(string endpoint)
        {
            return MakeRequest("GET", endpoint, Headers, (url, headers) => Http.Get(url, headers));
        }

        //
        // Post
        //

        public JObject Post(string endpoint, Dictionary<string, string> parameters)
        {
            var jsonHeaders = new Dictionary<string, string>(Headers);
            jsonHeaders["Content-Type"] = "application/json; charset=UTF-8";

            return MakeRequest("POST",
                               endpoint,
                               jsonHeaders,
                               (url, headers) => Http.Post(url,
                                                           JsonConvert.SerializeObject(parameters),
                                                           headers));
        }

        //
        // Private
        //

        internal JObject MakeRequest(string method,
                                     string endpoint,
                                     Dictionary<string, string> headers,
                                     Func<string, Dictionary<string, string>, string> request)
        {
            var url = MakeUrl(endpoint);
            try
            {
                return JObject.Parse(request(url, headers));
            }
            catch (WebException e)
            {
                throw MakeNetworkError(method, url, e);
            }
            catch (JsonException e)
            {
                throw MakeInvalidResponseError("Invalid JSON in response from '{0}'", url, e);
            }
        }

        internal string MakeUrl(string endpoint)
        {
            return BaseUrl + '/' + endpoint.TrimStart('/');
        }

        internal static ClientException MakeNetworkError(string method,
                                                         string url,
                                                         WebException original)
        {
            if (original.Status == WebExceptionStatus.ProtocolError)
                return MakeHttpError(method, url, (HttpWebResponse)original.Response, original);

            return new ClientException(ClientException.FailureReason.NetworkError,
                                       string.Format("{0} request to '{1}' failed", method, url),
                                       original);
        }

        private static ClientException MakeHttpError(string method,
                                                     string url,
                                                     HttpWebResponse response,
                                                     WebException original)
        {
            return new ClientException(ClientException.FailureReason.NetworkError,
                                       string.Format(
                                           "{0} request to '{1}' failed with HTTP status code {2}",
                                           method,
                                           url,
                                           response.StatusCode),
                                       original);
        }

        private static ClientException MakeInvalidResponseError(string format,
                                                                string url,
                                                                Exception original)
        {
            return new ClientException(ClientException.FailureReason.InvalidResponse,
                                       string.Format(format, url),
                                       original);
        }
    }
}
