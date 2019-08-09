// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using Xunit;
using PasswordManagerAccess.Common;
using System;
using System.Net.Http;
using System.Net;

namespace PasswordManagerAccess.Test
{
    internal class TestRestTransport: IRestTransport
    {
        public TestRestTransport Get(string response, HttpStatusCode status = HttpStatusCode.OK)
        {
            return Get("", response, status);
        }

        public TestRestTransport Get(string url, string response, HttpStatusCode status = HttpStatusCode.OK)
        {
            _responses.Add(new Response(HttpMethod.Get, url, response, status));
            return this;
        }

        public TestRestTransport Post(string response, HttpStatusCode status = HttpStatusCode.OK)
        {
            return Post("", response, status);
        }

        public TestRestTransport Post(string url, string response, HttpStatusCode status = HttpStatusCode.OK)
        {
            _responses.Add(new Response(HttpMethod.Post, url, response, status));
            return this;
        }

        public RestClient ToRestClient(string baseUrl = "https://does.not.matter")
        {
            return new RestClient(this, baseUrl);
        }

        //
        // Private
        //

        class Response
        {
            public readonly HttpMethod Method;
            public readonly string UrlFragment;
            public readonly string Content;
            public readonly HttpStatusCode Status;

            public Response(HttpMethod method, string urlFragment, string content, HttpStatusCode status)
            {
                Method = method;
                UrlFragment = urlFragment;
                Content = content;
                Status = status;
            }
        }

        Response AdvanceToNextResponse()
        {
            Assert.True(_currentIndex < _responses.Count, "Too many requests");
            return _responses[_currentIndex++];
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
            Assert.Equal(r.Method, method);
            Assert.Contains(r.UrlFragment, uri.AbsoluteUri);

            // Response
            allocatedResult.StatusCode = r.Status;
            allocatedResult.Content = r.Content;
            allocatedResult.Cookies = new Dictionary<string, string>();
            allocatedResult.RequestUri = uri;
        }

        void IDisposable.Dispose()
        {
        }

        private int _currentIndex = 0;
        private List<Response> _responses = new List<Response>();
    }
}
