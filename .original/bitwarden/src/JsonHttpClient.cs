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
            return Get(endpoint, Request);
        }

        public T Get<T>(string endpoint)
        {
            return Get(endpoint, Request<T>);
        }

        //
        // Post
        //

        public JObject Post(string endpoint, Dictionary<string, string> parameters)
        {
            return Post(endpoint, parameters, Request);
        }

        public T Post<T>(string endpoint, Dictionary<string, string> parameters)
        {
            return Post(endpoint, parameters, Request<T>);
        }

        //
        // Internal
        //

        internal T Get<T>(string endpoint,
                          Func<string,
                               string,
                               Dictionary<string, string>,
                               Func<string, Dictionary<string, string>, string>, T> request)
        {
            return request("GET", endpoint, Headers, (url, headers) => Http.Get(url, headers));
        }

        internal T Post<T>(string endpoint,
                           Dictionary<string, string> parameters,
                           Func<string,
                                string,
                                Dictionary<string, string>,
                                Func<string, Dictionary<string, string>, string>, T> request)
        {
            var jsonHeaders = new Dictionary<string, string>(Headers);
            jsonHeaders["Content-Type"] = "application/json; charset=UTF-8";

            return request("POST",
                           endpoint,
                           jsonHeaders,
                           (url, headers) => Http.Post(url,
                                                       JsonConvert.SerializeObject(parameters),
                                                       headers));
        }

        internal T Request<T>(string method,
                              string endpoint,
                              Dictionary<string, string> headers,
                              Func<string, Dictionary<string, string>, string> request)
        {
            return Request(method, endpoint, headers, request, JsonConvert.DeserializeObject<T>);
        }

        internal JObject Request(string method,
                                 string endpoint,
                                 Dictionary<string, string> headers,
                                 Func<string, Dictionary<string, string>, string> request)
        {
            return Request(method, endpoint, headers, request, JObject.Parse);
        }

        internal T Request<T>(string method,
                              string endpoint,
                              Dictionary<string, string> headers,
                              Func<string, Dictionary<string, string>, string> request,
                              Func<string, T> parse)
        {
            var url = MakeUrl(endpoint);
            try
            {
                return parse(request(url, headers));
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

        internal static ClientException MakeHttpError(string method,
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

        internal static ClientException MakeInvalidResponseError(string format,
                                                                 string url,
                                                                 Exception original)
        {
            return new ClientException(ClientException.FailureReason.InvalidResponse,
                                       string.Format(format, url),
                                       original);
        }
    }
}
