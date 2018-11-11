// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Web;

namespace Bitwarden
{
    internal class JsonHttpClient
    {
        public readonly IHttpClient Http;
        public readonly string BaseUrl;
        public readonly Dictionary<string, string> Headers;

        public JsonHttpClient(IHttpClient http, string baseUrl):
            this(http, baseUrl, new Dictionary<string, string>())
        {
        }

        public JsonHttpClient(IHttpClient http, string baseUrl, Dictionary<string, string> headers)
        {
            Http = http;
            BaseUrl = baseUrl.TrimEnd('/');
            Headers = headers;
        }

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
            return Post(endpoint, parameters, JsonContentType, JsonConvert.SerializeObject, Request);
        }

        public T Post<T>(string endpoint, Dictionary<string, string> parameters)
        {
            return Post(endpoint, parameters, JsonContentType, JsonConvert.SerializeObject, Request<T>);
        }

        public JObject PostForm(string endpoint, Dictionary<string, string> parameters)
        {
            return Post(endpoint, parameters, FormContentType, UrlEncode, Request);
        }

        public T PostForm<T>(string endpoint, Dictionary<string, string> parameters)
        {
            return Post(endpoint, parameters, FormContentType, UrlEncode, Request<T>);
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
                           string contentType,
                           Func<Dictionary<string, string>, string> serialize,
                           Func<string,
                                string,
                                Dictionary<string, string>,
                                Func<string, Dictionary<string, string>, string>, T> request)
        {
            var jsonHeaders = new Dictionary<string, string>(Headers);
            jsonHeaders["Accept"] = "application/json";
            jsonHeaders["Content-Type"] = contentType;

            return request("POST",
                           endpoint,
                           jsonHeaders,
                           (url, headers) => Http.Post(url, serialize(parameters), headers));
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
                              Func<string, Dictionary<string, string>, string> request)
        {
            return Request(method, endpoint, headers, request, JsonConvert.DeserializeObject<T>);
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

        // TODO: Test this
        internal string UrlEncode(Dictionary<string, string> parameters)
        {
            return string.Join("&",
                               parameters.Select(i => string.Format("{0}={1}",
                                                                    HttpUtility.UrlEncode(i.Key),
                                                                    HttpUtility.UrlEncode(i.Value))));
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

        private const string JsonContentType = "application/json; charset=UTF-8";
        private const string FormContentType = "application/x-www-form-urlencoded; charset=UTF-8";
    }
}
