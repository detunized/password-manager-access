// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using Xunit;
using PasswordManagerAccess.Common;
using System;
using System.Net.Http;
using System.Net;
using System.Linq;

namespace PasswordManagerAccess.Test
{
    // TODO: Stupid name, come up with a better one!
    internal class TestRestTransport: IRestTransport
    {
        //
        // GET
        //

        public TestRestTransport Get(string response, HttpStatusCode status = HttpStatusCode.OK)
        {
            _responses.Add(new Response(HttpMethod.Get, response, status));
            return this;
        }

        //
        // POST
        //

        public TestRestTransport Post(string response, HttpStatusCode status = HttpStatusCode.OK)
        {
            _responses.Add(new Response(HttpMethod.Post, response, status));
            return this;
        }

        public RestClient ToRestClient(string baseUrl = "https://does.not.matter")
        {
            return new RestClient(this, baseUrl);
        }

        //
        // Expect
        //

        public TestRestTransport ExpectUrl(params string[] urlFragments)
        {
            var e = GetLastExpected();
            e.UrlFragments = e.UrlFragments.Concat(urlFragments).ToArray();
            return this;
        }

        public TestRestTransport ExpectContent(params string[] contentFragments)
        {
            var e = GetLastExpected();
            e.ContentFragments = e.ContentFragments.Concat(contentFragments).ToArray();
            return this;
        }

        //
        // Private
        //

        private class Request
        {
            public HttpMethod Method;
            public string[] UrlFragments = NoFragments;
            public string[] ContentFragments = NoFragments;
            public Dictionary<string, string> PartialHeaders = NoHeaders;
            public Dictionary<string, string> PartialCookies = NoCookies;

            public Request(HttpMethod method)
            {
                Method = method;
            }
        }

        private class Response
        {
            // Returned to the caller
            public readonly string Content;
            public readonly HttpStatusCode Status;

            // Expected to be received from the caller
            public Request Expected;

            public Response(HttpMethod method, string content, HttpStatusCode status)
            {
                Content = content;
                Status = status;
                Expected = new Request(method);
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

        private Request GetLastExpected()
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

            var contentStr = content.ReadAsStringAsync().Result;
            foreach (var c in e.ContentFragments)
                Assert.Contains(c, contentStr);

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
