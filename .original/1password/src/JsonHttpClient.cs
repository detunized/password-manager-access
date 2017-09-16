// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Net;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace OnePassword
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
            return MakeRequest(endpoint, url => Http.Get(url, Headers));
        }

        //
        // Post
        //

        public JObject Post(string endpoint, Dictionary<string, object> parameters)
        {
            var jsonHeaders = new Dictionary<string, string>(Headers);
            jsonHeaders["Content-Type"] = "application/json; charset=UTF-8";

            return MakeRequest(endpoint,
                               url => Http.Post(url,
                                                JsonConvert.SerializeObject(parameters),
                                                jsonHeaders));
        }

        //
        // Put
        //

        public JObject Put(string endpoint)
        {
            return MakeRequest(endpoint, url => Http.Put(url, Headers));
        }

        //
        // Private
        //

        internal JObject MakeRequest(string endpoint, Func<string, string> request)
        {
            var url = MakeUrl(endpoint);
            try
            {
                return JObject.Parse(request(url));
            }
            catch (WebException e)
            {
                throw MakeNetworkError(url, e);
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

        internal static ClientException MakeNetworkError(string url, WebException original)
        {
            if (original.Status == WebExceptionStatus.ProtocolError)
                return MakeHttpError(url, (HttpWebResponse)original.Response, original);

            return new ClientException(ClientException.FailureReason.NetworkError,
                                       string.Format("Request to '{0}' failed", url),
                                       original);
        }

        private static ClientException MakeHttpError(string url,
                                                     HttpWebResponse response,
                                                     WebException original)
        {
            return new ClientException(ClientException.FailureReason.NetworkError,
                                       string.Format(
                                           "{0} request to '{1}' failed with HTTP status code {2}",
                                           response.Method,
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
