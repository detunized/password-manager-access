// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using Xunit;
using System.Collections.Generic;

namespace PasswordManagerAccess.Common
{
    internal class TestHttpClient: IHttpClient
    {
        public TestHttpClient Get(string response)
        {
            return Get("", response);
        }

        public TestHttpClient Get(string url, string response)
        {
            _responses.Add(new Response(Method.Get, url, response));
            return this;
        }

        public TestHttpClient Post(string response)
        {
            return Post("", response);
        }

        public TestHttpClient Post(string url, string response)
        {
            _responses.Add(new Response(Method.Post, url, response));
            return this;
        }

        public JsonHttpClient ToJsonClient(string baseUrl = "https://does.not.matter")
        {
            return new JsonHttpClient(this, baseUrl);
        }

        //
        // Private
        //

        enum Method
        {
            Get,
            Post,
        }

        class Response
        {
            public readonly Method Method;
            public readonly string UrlFragment;
            public readonly string Content;

            public Response(Method method, string urlFragment, string content)
            {
                Method = method;
                UrlFragment = urlFragment;
                Content = content;
            }
        }

        string IHttpClient.Get(string url, Dictionary<string, string> headers)
        {
            var r = AdvanceToNextResponse();
            Assert.Equal(Method.Get, r.Method); // TODO: Better messages
            Assert.Contains(r.UrlFragment, url);

            return r.Content;
        }

        string IHttpClient.Post(string url, string content, Dictionary<string, string> headers)
        {
            var r = AdvanceToNextResponse();
            Assert.Equal(Method.Post, r.Method); // TODO: Better messages
            Assert.Contains(r.UrlFragment, url);

            return r.Content;
        }

        Response AdvanceToNextResponse()
        {
            Assert.True(_currentIndex < _responses.Count, "Too many requests");
            return _responses[_currentIndex++];
        }

        private int _currentIndex = 0;
        private List<Response> _responses = new List<Response>();
    }
}
