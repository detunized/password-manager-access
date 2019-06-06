// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
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

        public bool IsSuccessful => (int)StatusCode / 100 == 2 && Error == null;
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

        public RestResponse PostForm(string url,
                                     PostParameters parameters,
                                     HttpHeaders headers = null,
                                     HttpCookies cookies = null)
        {
            var content = new H.FormUrlEncodedContent(
                parameters.Select(kv => new KeyValuePair<string, string>(kv.Key, kv.Value.ToString())));

            return MakeRequest(url, H.HttpMethod.Post, content, headers, cookies);
        }

        private RestResponse MakeRequest(string url,
                                         H.HttpMethod method,
                                         H.HttpContent content = null,
                                         HttpHeaders headers = null,
                                         HttpCookies cookies = null)
        {
            var response = new RestResponse();
            try
            {
                var uri = new Uri(url);
                var request = new H.HttpRequestMessage(method, url) { Content = content };

                // Set headers
                if (headers != null)
                    foreach (var h in headers)
                        request.Headers.Add(h.Key, h.Value);

                //HttpHandler.CookieContainer = new CookieContainer();
                //if (cookies != null)
                //    foreach (var c in cookies)
                //        HttpHandler.CookieContainer.Add(new Cookie(c.Key, c.Value, "/", uri.Host));

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
                foreach (var h in result.Headers.GetValues("Set-Cookie"))
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
