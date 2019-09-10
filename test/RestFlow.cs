// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using PasswordManagerAccess.Common;
using Xunit;

namespace PasswordManagerAccess.Test
{
    internal class RestFlow: IRestTransport
    {
        //
        // GET
        //

        public RestFlow Get(string response, HttpStatusCode status = HttpStatusCode.OK, Exception error = null)
        {
            _responses.Add(new Response(HttpMethod.Get, response, status, error));
            return this;
        }

        public RestFlow Get(string response, Exception error)
        {
            return Get(response, HttpStatusCode.OK, error);
        }

        //
        // POST
        //

        public RestFlow Post(string response, HttpStatusCode status = HttpStatusCode.OK, Exception error = null)
        {
            _responses.Add(new Response(HttpMethod.Post, response, status, error));
            return this;
        }

        public RestFlow Post(string response, Exception error)
        {
            return Post(response, HttpStatusCode.OK, error);
        }

        public RestClient ToRestClient(string baseUrl = "https://does.not.matter")
        {
            return new RestClient(this, baseUrl);
        }

        //
        // Expect
        //

        public RestFlow ExpectUrl(params string[] urlFragments)
        {
            var e = GetLastExpected();
            e.UrlFragments = e.UrlFragments.Concat(urlFragments).ToArray();
            return this;
        }

        public RestFlow ExpectContent(params string[] contentFragments)
        {
            var e = GetLastExpected();
            e.ContentFragments = e.ContentFragments.Concat(contentFragments).ToArray();
            return this;
        }

        public RestFlow ExpectContent(Action<string> verify)
        {
            var e = GetLastExpected();
            e.ContentVerifiers.Add(verify);
            return this;
        }

        public RestFlow ExpectHeader(string name, string value)
        {
            return ExpectHeaders(new Dictionary<string, string> {{name, value}});
        }

        public RestFlow ExpectHeaders(Dictionary<string, string> partialHeaders)
        {
            var e = GetLastExpected();
            e.PartialHeaders = e.PartialHeaders.Merge(partialHeaders);
            return this;
        }

        public RestFlow ExpectCookie(string name, string value)
        {
            return ExpectCookies(new Dictionary<string, string> {{name, value}});
        }

        public RestFlow ExpectCookies(Dictionary<string, string> partialCookies)
        {
            var e = GetLastExpected();
            e.PartialCookies = e.PartialCookies.Merge(partialCookies);
            return this;
        }

        //
        // Private
        //

        private class Expected
        {
            public HttpMethod Method;
            public string[] UrlFragments = NoFragments;
            public string[] ContentFragments = NoFragments;
            public Dictionary<string, string> PartialHeaders = NoHeaders;
            public Dictionary<string, string> PartialCookies = NoCookies;

            public List<Action<string>> ContentVerifiers = new List<Action<string>>();

            public Expected(HttpMethod method)
            {
                Method = method;
            }
        }

        private class Response
        {
            // Returned to the caller
            public readonly string Content;
            public readonly HttpStatusCode Status;
            public readonly Exception Error;

            // Expected to be received from the caller
            public Expected Expected;

            public Response(HttpMethod method, string content, HttpStatusCode status, Exception error)
            {
                Content = content;
                Status = status;
                Error = error;
                Expected = new Expected(method);
            }
        }

        private Response AdvanceToNextResponse()
        {
            Assert.True(_currentIndex < _responses.Count, "Too many requests");
            return _responses[_currentIndex++];
        }

        private Response GetLastResponse()
        {
            if (_responses.Count == 0)
                throw new InvalidOperationException("Expect should be following Get or Set");

            return _responses.Last();
        }

        private Expected GetLastExpected()
        {
            return GetLastResponse().Expected;
        }

        void IRestTransport.MakeRequest(Uri uri,
                                        HttpMethod method,
                                        HttpContent content,
                                        Dictionary<string, string> headers,
                                        Dictionary<string, string> cookies,
                                        int maxRedirectCount,
                                        RestResponse allocatedResult)
        {
            var r = AdvanceToNextResponse();
            var e = r.Expected;

            Assert.Equal(e.Method, method);

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
                Assert.Equal(header.Value, headers[header.Key]);
            }

            // TODO: Better messages
            foreach (var cookie in e.PartialCookies)
            {
                Assert.Contains(cookie.Key, cookies.Keys);
                Assert.Equal(cookie.Value, cookies[cookie.Key]);
            }

            // Response
            allocatedResult.StatusCode = r.Status;
            allocatedResult.Content = r.Content;
            allocatedResult.Error = r.Error;
            allocatedResult.Cookies = new Dictionary<string, string>();
            allocatedResult.RequestUri = uri;
        }

        void IDisposable.Dispose()
        {
        }

        private static readonly string[] NoFragments = new string[0];
        private static readonly Dictionary<string, string> NoHeaders = new Dictionary<string, string>();
        private static readonly Dictionary<string, string> NoCookies = new Dictionary<string, string>();

        private int _currentIndex = 0;
        private List<Response> _responses = new List<Response>();
    }
}
