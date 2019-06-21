// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;
using H = System.Net.Http;

namespace PasswordManagerAccess.Common
{
    using PostParameters = Dictionary<string, object>;
    using HttpHeaders = Dictionary<string, string>;
    using HttpCookies = Dictionary<string, string>;
    using SendAsyncType = Func<H.HttpRequestMessage, Task<H.HttpResponseMessage>>;

    internal class RestResponse
    {
        public HttpStatusCode StatusCode { get; internal set; }
        public string Content { get; internal set; }
        public Exception Error { get; internal set; }
        public Dictionary<string, string> Cookies { get; internal set; }

        // On HTTP 2xx and no exceptions
        public bool IsSuccessful => IsHttpOk && !HasError;

        // On HTTP 2xx
        public bool IsHttpOk => (int)StatusCode / 100 == 2;

        // On HTTP other than 2xx, but not other exceptions
        public bool IsHttpError => !IsHttpOk && !HasError;

        // On other error
        public bool HasError => Error != null;
    }

    internal class RestResponse<T>: RestResponse
    {
        public T Data { get; internal set; }
    }

    internal class RestMessageHandler: H.HttpMessageHandler
    {
        public RestMessageHandler(SendAsyncType sendAsync)
        {
            _sendAsync = sendAsync;
        }

        protected override Task<H.HttpResponseMessage> SendAsync(H.HttpRequestMessage request,
                                                                 CancellationToken cancellationToken)
        {
            return _sendAsync(request);
        }

        private readonly SendAsyncType _sendAsync;
    }

    internal class RestClient: IDisposable
    {
        public readonly H.HttpClient Http;

        public RestClient()
        {
            Http = new H.HttpClient(new H.HttpClientHandler() { UseCookies = false }, true);
        }

        public RestClient(SendAsyncType sendAsync)
        {
            Http = new H.HttpClient(new RestMessageHandler(sendAsync), true);
        }

        public RestResponse Get(string url, HttpHeaders headers = null, HttpCookies cookies = null)
        {
            return MakeRequest(url, H.HttpMethod.Get, null, headers, cookies);
        }

        public RestResponse<T> Get<T>(string url, HttpHeaders headers = null, HttpCookies cookies = null)
        {
            return MakeRequest<T>(url, H.HttpMethod.Get, null, headers, cookies, JsonConvert.DeserializeObject<T>);
        }

        public RestResponse PostForm(string url,
                                     PostParameters parameters,
                                     HttpHeaders headers = null,
                                     HttpCookies cookies = null)
        {
            var content = new H.FormUrlEncodedContent(
                parameters.Select(kv => new KeyValuePair<string, string>(kv.Key, kv.Value.ToString())));

            return MakeRequest(url, H.HttpMethod.Post, content, headers, cookies, () => new RestResponse());
        }

        private RestResponse<T> MakeRequest<T>(string url,
                                               H.HttpMethod method,
                                               H.HttpContent content,
                                               HttpHeaders headers,
                                               HttpCookies cookies,
                                               Func<string, T> deserialize)
        {
            var response = MakeRequest(url, method, content, headers, cookies, () => new RestResponse<T>());
            if (response.Error != null)
                return response;

            // Only deserialize when HTTP call succeeded, even with non 2XX code
            try
            {
                response.Data = deserialize(response.Content);
            }
            catch (Exception e) // TODO: Not a good practice, see how to catch only specific exceptions
            {
                response.Error = e;
            }

            return response;
        }

        private RestResponse MakeRequest(string url,
                                         H.HttpMethod method,
                                         H.HttpContent content,
                                         HttpHeaders headers,
                                         HttpCookies cookies)
        {
            return MakeRequest(url, method, content, headers, cookies, () => new RestResponse());
        }

        private TResponse MakeRequest<TResponse>(string url,
                                                 H.HttpMethod method,
                                                 H.HttpContent content,
                                                 HttpHeaders headers,
                                                 HttpCookies cookies,
                                                 Func<TResponse> responseFactory) where TResponse: RestResponse
        {
            var response = responseFactory();
            try
            {
                var uri = new Uri(url);
                var request = new H.HttpRequestMessage(method, url) { Content = content };

                // Set headers
                if (headers != null)
                    foreach (var h in headers)
                        request.Headers.Add(h.Key, h.Value);

                // Set cookies
                if (cookies != null)
                {
                    var headerValue = string.Join("; ", cookies.Select(x => $"{x.Key}={x.Value}"));
                    request.Headers.TryAddWithoutValidation("Cookie", headerValue);
                }

                // Don't use .Result here but rather .GetAwaiter().GetResult()
                // It produces a nicer call stack and no AggregateException nonsense
                // https://stackoverflow.com/a/36427080/362938
                var result = Http.SendAsync(request).GetAwaiter().GetResult();

                response.StatusCode = result.StatusCode;
                response.Content = result.Content.ReadAsStringAsync().GetAwaiter().GetResult();

                // Parse cookies
                var jar = new CookieContainer();
                if (result.Headers.Contains(SetCookieHeader))
                    foreach (var h in result.Headers.GetValues(SetCookieHeader))
                        jar.SetCookies(uri, h);

                response.Cookies = jar.GetCookies(uri)
                    .Cast<Cookie>()
                    .ToDictionary(x => x.Name, x => x.Value);
            }
            catch (H.HttpRequestException e)
            {
                response.Error = e;
            }

            return response;
        }

        private const string SetCookieHeader = "Set-Cookie";

        //
        // IDsposable
        //

        private bool disposedValue = false; // To detect redundant calls

        void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    Http.Dispose();
                }

                disposedValue = true;
            }
        }

        public void Dispose()
        {
            Dispose(true);
        }
    }
}
