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
            return Get(url, response, NoHeaders, status);
        }

        public TestRestTransport Get(string url,
                                     string response,
                                     Dictionary<string, string> partialHeaders,
                                     HttpStatusCode status = HttpStatusCode.OK)
        {
            _responses.Add(new Response(HttpMethod.Get, url, partialHeaders ?? NoHeaders, response, status));
            return this;
        }

        public TestRestTransport Post(string response, HttpStatusCode status = HttpStatusCode.OK)
        {
            return Post("", response, status);
        }

        public TestRestTransport Post(string url, string response, HttpStatusCode status = HttpStatusCode.OK)
        {
            return Post(url, response, NoHeaders, status);
        }

        public TestRestTransport Post(string url,
                                      string response,
                                      Dictionary<string, string> partialHeaders,
                                      HttpStatusCode status = HttpStatusCode.OK)
        {
            _responses.Add(new Response(HttpMethod.Post, url, partialHeaders ?? NoHeaders, response, status));
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
            // Expected
            public readonly HttpMethod Method;
            public readonly string UrlFragment;
            public readonly Dictionary<string, string> PartialHeaders;

            // Return
            public readonly string Content;
            public readonly HttpStatusCode Status;

            public Response(HttpMethod method,
                            string urlFragment,
                            Dictionary<string, string> partialHeaders,
                            string content,
                            HttpStatusCode status)
            {
                Method = method;
                UrlFragment = urlFragment;
                PartialHeaders = partialHeaders;

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

            foreach (var header in r.PartialHeaders)
            {
                Assert.Contains(header.Key, headers.Keys);
                Assert.Equal(header.Value, headers[header.Key]);
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

        private static readonly Dictionary<string, string> NoHeaders = new Dictionary<string, string>();

        private int _currentIndex = 0;
        private List<Response> _responses = new List<Response>();
    }
}
