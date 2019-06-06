// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace PasswordManagerAccess.Common
{
    using HttpHeaders = Dictionary<string, string>;
    using PostParameters = Dictionary<string, object>;

    // TODO: An idea is to return an Either-like object:
    //
    // internal class JsonResult<T>
    // {
    //     public T Response;
    //     public string RawResponse;
    //     public int HttpStatus;
    //     public Exception Error;
    // }
    //
    // It seems better than throwing exceptions around. The added benefit is that
    // the response is always available, even on error, when the HttpClient throws
    // an exception and we have to fish out the response content from it.

    // TODO: Maybe not such a good idea to call this JsonHttp as it handles forms and raw requests now.
    //       Rename it to something more appropriate.
    internal class JsonHttpClient
    {
        public readonly IHttpClient Http;
        public readonly string BaseUrl;
        public readonly HttpHeaders Headers;

        public JsonHttpClient(IHttpClient http, string baseUrl) :
            this(http, baseUrl, new HttpHeaders())
        {
        }

        public JsonHttpClient(IHttpClient http, string baseUrl, HttpHeaders headers)
        {
            Http = http;
            BaseUrl = baseUrl.TrimEnd('/');
            Headers = headers;
        }

        //
        // Get
        //

        public string GetRaw(string endpoint)
        {
            return Get(endpoint, RequestRaw);
        }

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

        public string PostRaw(string endpoint, PostParameters parameters)
        {
            return Post(endpoint, parameters, JsonContentType, JsonConvert.SerializeObject, RequestRaw);
        }

        public JObject Post(string endpoint, PostParameters parameters)
        {
            return Post(endpoint, parameters, JsonContentType, JsonConvert.SerializeObject, Request);
        }

        public T Post<T>(string endpoint, PostParameters parameters)
        {
            return Post(endpoint, parameters, JsonContentType, JsonConvert.SerializeObject, Request<T>);
        }

        public JObject PostForm(string endpoint, PostParameters parameters)
        {
            return Post(endpoint, parameters, FormContentType, UrlEncode, Request);
        }

        public T PostForm<T>(string endpoint, PostParameters parameters)
        {
            return Post(endpoint, parameters, FormContentType, UrlEncode, Request<T>);
        }

        //
        // Internal
        //

        internal T Get<T>(string endpoint,
                          Func<string,
                               string,
                               HttpHeaders,
                               Func<string, HttpHeaders, string>, T> request)
        {
            return request("GET", endpoint, Headers, (url, headers) => Http.Get(url, headers));
        }

        internal T Post<T>(string endpoint,
                           PostParameters parameters,
                           string contentType,
                           Func<PostParameters, string> serialize,
                           Func<string,
                                string,
                                HttpHeaders,
                                Func<string, HttpHeaders, string>, T> request)
        {
            var jsonHeaders = new HttpHeaders(Headers);
            jsonHeaders["Accept"] = "application/json";
            jsonHeaders["Content-Type"] = contentType;

            return request("POST",
                           endpoint,
                           jsonHeaders,
                           (url, headers) => Http.Post(url, serialize(parameters), headers));
        }

        internal string RequestRaw(string method,
                                   string endpoint,
                                   HttpHeaders headers,
                                   Func<string, HttpHeaders, string> request)
        {
            return Request(method, endpoint, headers, request, s => s);
        }

        internal JObject Request(string method,
                                 string endpoint,
                                 HttpHeaders headers,
                                 Func<string, HttpHeaders, string> request)
        {
            return Request(method, endpoint, headers, request, JObject.Parse);
        }

        internal T Request<T>(string method,
                              string endpoint,
                              HttpHeaders headers,
                              Func<string, HttpHeaders, string> request)
        {
            return Request(method, endpoint, headers, request, JsonConvert.DeserializeObject<T>);
        }

        internal T Request<T>(string method,
                              string endpoint,
                              HttpHeaders headers,
                              Func<string, HttpHeaders, string> request,
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
                throw new InternalErrorException($"Invalid JSON in response from '{url}'", e);
            }
        }

        internal string MakeUrl(string endpoint)
        {
            return BaseUrl + '/' + endpoint.TrimStart('/');
        }

        internal static string UrlEncode(PostParameters parameters)
        {
            return string.Join("&",
                               parameters.Select(i => string.Format("{0}={1}",
                                                                    WebUtility.UrlEncode(i.Key),
                                                                    WebUtility.UrlEncode(i.Value.ToString()))));
        }

        internal static NetworkErrorException MakeNetworkError(string method, string url, WebException original)
        {
            if (original.Status == WebExceptionStatus.ProtocolError)
                return MakeHttpError(method, url, (HttpWebResponse)original.Response, original);

            return new NetworkErrorException($"{method} request to '{url}' failed", original);
        }

        internal static NetworkErrorException MakeHttpError(string method,
                                                            string url,
                                                            HttpWebResponse response,
                                                            WebException original)
        {
            return new NetworkErrorException(
                string.Format("{0} request to '{1}' failed with HTTP status code {2} ({3})",
                              method,
                              url,
                              response.StatusCode,
                              (int)response.StatusCode),
                original);
        }

        //
        // Private
        //

        private const string JsonContentType = "application/json; charset=UTF-8";
        private const string FormContentType = "application/x-www-form-urlencoded; charset=UTF-8";
    }
}
