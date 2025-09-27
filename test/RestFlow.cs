// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using PasswordManagerAccess.Common;
using Xunit;

namespace PasswordManagerAccess.Test
{
    internal class RestFlow : HttpMessageHandler, IRestTransport
    {
        public bool UseSystemJson { get; init; }
        public bool Disposed { get; private set; }

        public class ResponseContent
        {
            public readonly bool IsBinary;
            public readonly string Text;
            public readonly byte[] Binary;

            private ResponseContent(string text)
            {
                IsBinary = false;
                Text = text;
                Binary = null;
            }

            private ResponseContent(byte[] binary)
            {
                IsBinary = true;
                Binary = binary;
                Text = null;
            }

            public static implicit operator ResponseContent(string text) => new ResponseContent(text);

            public static implicit operator ResponseContent(byte[] binary) => new ResponseContent(binary);
        }

        //
        // GET
        //

        public RestFlow Get(
            ResponseContent response,
            HttpStatusCode status = HttpStatusCode.OK,
            Dictionary<string, string> headers = null,
            Dictionary<string, string> cookies = null,
            string responseUrl = null,
            Exception error = null
        )
        {
            _responses.Add(
                new Response(
                    Method: HttpMethod.Get,
                    Content: response,
                    Status: status,
                    Headers: headers ?? [],
                    Cookies: cookies ?? [],
                    ResponseUrl: responseUrl,
                    Error: error
                )
            );
            return this;
        }

        public RestFlow Get(ResponseContent response, Exception error)
        {
            return Get(response, HttpStatusCode.OK, [], [], NoResponseUrl, error);
        }

        public RestFlow Get(Exception error)
        {
            return Get("", error);
        }

        //
        // POST
        //

        public RestFlow Post(
            ResponseContent response,
            HttpStatusCode status = HttpStatusCode.OK,
            Dictionary<string, string> headers = null,
            Dictionary<string, string> cookies = null,
            string responseUrl = null,
            Exception error = null
        )
        {
            _responses.Add(
                new Response(
                    Method: HttpMethod.Post,
                    Content: response,
                    Status: status,
                    Headers: headers ?? [],
                    Cookies: cookies ?? [],
                    ResponseUrl: responseUrl,
                    Error: error
                )
            );
            return this;
        }

        public RestFlow Post(ResponseContent response, Exception error)
        {
            return Post(response, HttpStatusCode.OK, [], [], NoResponseUrl, error);
        }

        public RestFlow Post(Exception error)
        {
            return Post("", error);
        }

        //
        // PUT
        //

        public RestFlow Put(
            ResponseContent response,
            HttpStatusCode status = HttpStatusCode.OK,
            Dictionary<string, string> headers = null,
            Dictionary<string, string> cookies = null,
            string responseUrl = null,
            Exception error = null
        )
        {
            _responses.Add(
                new Response(
                    Method: HttpMethod.Put,
                    Content: response,
                    Status: status,
                    Headers: headers ?? [],
                    Cookies: cookies ?? [],
                    ResponseUrl: responseUrl,
                    Error: error
                )
            );
            return this;
        }

        public RestFlow Put(ResponseContent response, Exception error)
        {
            return Put(response, HttpStatusCode.OK, [], [], NoResponseUrl, error);
        }

        public RestFlow Put(Exception error)
        {
            return Put("", error);
        }

        //
        // RestClient
        //

        public RestClient ToRestClient(string baseUrl = "https://does.not.matter")
        {
            return new RestClient(this, baseUrl, useSystemJson: UseSystemJson);
        }

        public static implicit operator RestClient(RestFlow flow)
        {
            return flow.ToRestClient();
        }

        //
        // Expect
        //

        public RestFlow ExpectUrl(params string[] urlFragments)
        {
            var e = GetLastExpected();
            e.UrlFragments.AddRange(urlFragments);
            return this;
        }

        public RestFlow ExpectContent(params string[] contentFragments)
        {
            var e = GetLastExpected();
            e.ContentFragments.AddRange(contentFragments);
            return this;
        }

        public RestFlow ExpectContent(Action<string> verify)
        {
            var e = GetLastExpected();
            e.ContentVerifiers.Add(verify);
            return this;
        }

        public RestFlow ExpectHeader(string name, params string[] values)
        {
            var e = GetLastExpected();
            if (e.PartialHeaders.TryGetValue(name, out var existing))
                existing.AddRange(values);
            else
                e.PartialHeaders[name] = values.ToList();
            return this;
        }

        public RestFlow ExpectCookie(string name, params string[] values)
        {
            var e = GetLastExpected();
            if (e.PartialCookies.TryGetValue(name, out var existing))
                existing.AddRange(values);
            else
                e.PartialCookies[name] = values.ToList();
            return this;
        }

        //
        // Private
        //

        private record Expected(HttpMethod Method)
        {
            public List<string> UrlFragments { get; } = [];
            public List<string> ContentFragments { get; } = [];
            public Dictionary<string, List<string>> PartialHeaders { get; } = [];
            public Dictionary<string, List<string>> PartialCookies { get; } = [];
            public List<Action<string>> ContentVerifiers { get; } = [];
        }

        private record Response(
            HttpMethod Method,
            ResponseContent Content,
            HttpStatusCode Status,
            Dictionary<string, string> Headers,
            Dictionary<string, string> Cookies,
            string ResponseUrl,
            Exception Error
        )
        {
            // Expected to be received from the caller
            public Expected Expected { get; } = new(Method);
        }

        private Response GetLastResponse()
        {
            if (_responses.Count == 0)
                throw new InvalidOperationException("Expect should be following a call to Get, Post or Put");

            return _responses.Last();
        }

        private Expected GetLastExpected()
        {
            return GetLastResponse().Expected;
        }

        //
        // IRestTransport implementation
        //

        public void MakeRequest<TContent>(
            Uri uri,
            HttpMethod method,
            HttpContent content,
            IReadOnlyDictionary<string, string> headers,
            IReadOnlyDictionary<string, string> cookies,
            int maxRedirectCount,
            RestResponse<TContent> allocatedResult
        )
        {
            // Make sure we don't try to request in parallel during testing.
            // Otherwise, RestFlow has to be reworked to be made thread safe.
            lock (_requestLock)
                MakeRequestLocked(uri, method, content, headers, cookies, allocatedResult);
        }

        // TODO: Fix this!
#pragma warning disable CS1998 // Async method lacks 'await' operators and will run synchronously
        public async Task MakeRequestAsync<TContent>(
#pragma warning restore CS1998 // Async method lacks 'await' operators and will run synchronously
            Uri uri,
            HttpMethod method,
            HttpContent content,
            IReadOnlyDictionary<string, string> headers,
            IReadOnlyDictionary<string, string> cookies,
            int maxRedirectCount,
            RestResponse<TContent> allocatedResult,
            CancellationToken cancellationToken
        )
        {
            // TODO: Implement this properly
            MakeRequest(uri, method, content, headers, cookies, maxRedirectCount, allocatedResult);
        }

        //
        // HttpMessageHandler implementation
        //

        // This adapter fits the RestFlow into the RestClient/HttpClient pipeline
        // TODO: This will not be needed once we switch over to the RestClient completely
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            // The cookies are coming in the headers, so we have to parse them out
            var cookies = new Dictionary<string, string>();
            if (request.Headers.TryGetValues("Cookie", out var cookieHeader))
            {
                var cc = new CookieContainer();
                cc.SetCookies(request.RequestUri!, cookieHeader.JoinToString("; "));
                cookies = cc.GetCookies(request.RequestUri).ToDictionary(x => x.Name, x => x.Value);
            }

            var result = new RestResponse<string>();
            MakeRequest(
                request.RequestUri,
                request.Method,
                request.Content,
                request.Headers.ToDictionary(x => x.Key, x => x.Value.First()),
                cookies,
                0,
                result
            );

            var response = new HttpResponseMessage(result.StatusCode) { Content = new StringContent(result.Content) };

            foreach (var header in result.Headers)
                response.Headers.TryAddWithoutValidation(header.Key, header.Value);

            // Need to convert the cookies into the Set-Cookie headers for RestClient to pick them up
            foreach (var cookie in result.Cookies)
                response.Headers.TryAddWithoutValidation("Set-Cookie", $"{cookie.Key}={cookie.Value}");

            return Task.FromResult(response);
        }

        private void MakeRequestLocked<TContent>(
            Uri uri,
            HttpMethod method,
            HttpContent content,
            IReadOnlyDictionary<string, string> headers,
            IReadOnlyDictionary<string, string> cookies,
            RestResponse<TContent> allocatedResult
        )
        {
            if (_currentIndex >= _responses.Count)
                Assert.Fail($"Too many requests, there's no response available for {method} to '{uri}'");

            var r = _responses[_currentIndex++];
            var e = r.Expected;
            string ErrorMessage(string text) => $"{text} for request at index {_currentIndex - 1} to '{uri}'";

            Assert.True(e.Method == method, ErrorMessage($"Expected {e.Method}, got {method}"));

            foreach (var u in e.UrlFragments)
                Assert.Contains(u, uri.AbsoluteUri);

            // Not all requests have content (GET has none, for example)
            if (content != null)
            {
                var contentStr = content.ReadAsStringAsync().Result;
                foreach (var c in e.ContentFragments)
                    Assert.Contains(c, contentStr);

                foreach (var v in e.ContentVerifiers)
                    v(contentStr);
            }

            // TODO: Better messages
            foreach (var header in e.PartialHeaders)
            {
                Assert.Contains(header.Key, headers.Keys);
                foreach (var expectedValue in header.Value)
                    Assert.Contains(expectedValue, headers[header.Key]);
            }

            // TODO: Better messages
            foreach (var cookie in e.PartialCookies)
            {
                Assert.Contains(cookie.Key, cookies.Keys);
                foreach (var expectedValue in cookie.Value)
                    Assert.Contains(expectedValue, cookies[cookie.Key]);
            }

            // Response
            allocatedResult.StatusCode = r.Status;
            allocatedResult.Headers = r.Headers;
            allocatedResult.Error = r.Error;
            allocatedResult.Cookies = r.Cookies;
            allocatedResult.RequestUri = r.ResponseUrl == null ? uri : new Uri(r.ResponseUrl);

            switch (allocatedResult)
            {
                case RestResponse<string> text:
                    Assert.False(r.Content.IsBinary, ErrorMessage("Expected a text request, got binary"));
                    text.Content = r.Content.Text;
                    break;
                case RestResponse<byte[]> text:
                    Assert.True(r.Content.IsBinary, ErrorMessage("Expected a binary request, got text"));
                    text.Content = r.Content.Binary;
                    break;
                default:
                    throw new ArgumentException($"Unsupported content type {typeof(TContent)}");
            }
        }

        //
        // IDisposable implementation
        //
        public new void Dispose()
        {
            Disposed = true;
        }

        //
        // Data
        //

        private const string NoResponseUrl = null;

        private int _currentIndex;
        private readonly List<Response> _responses = [];

        private readonly object _requestLock = new();
    }
}
