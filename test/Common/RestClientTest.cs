// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using PasswordManagerAccess.Common;
using Xunit;

namespace PasswordManagerAccess.Test.Common
{
    using SendAsyncType = Func<HttpRequestMessage, Task<HttpResponseMessage>>;

    public class RestClientTest
    {
        [Fact]
        public void Get_works()
        {
            var response = Serve("yo").Get(Url);

            Assert.True(response.IsSuccessful);
            Assert.Equal("yo", response.Content);
        }

        [Fact]
        public void Get_sets_url()
        {
            InRequest(
                rest => rest.Get(Url),
                request =>
                {
                    Assert.Equal(Url, request.RequestUri.AbsoluteUri);
                });
        }

        [Fact]
        public void Get_sends_headers()
        {
            InRequest(
                rest => rest.Get(Url, new Dictionary<string, string> { { "header", "value" } }),
                request =>
                {
                    Assert.Equal(new[] { "value" }, request.Headers.GetValues("header"));
                });
        }

        [Fact]
        public void Get_sends_cookies()
        {
            InRequest(
                rest => rest.Get(Url, null, new Dictionary<string, string> { { "cookie", "value" } }),
                request =>
                {
                    Assert.Equal(new[] { "cookie=value" }, request.Headers.GetValues("Cookie"));
                });
        }

        [Fact]
        public void Get_decodes_json()
        {
            var response = Serve("{'Key': 'k', 'Value': 'v'}").Get<KeyValuePair<string, string>>(Url);

            Assert.True(response.IsSuccessful);
            Assert.Equal(new KeyValuePair<string, string>("k", "v"), response.Data);
        }

        [Fact]
        public void PostJson_sends_json_headers()
        {
            InRequest(
                rest => rest.PostJson(Url, new Dictionary<string, object>()),
                request => {
                    Assert.Equal(new[] { "application/json; charset=utf-8" },
                                 request.Content.Headers.GetValues("Content-type"));
                });
        }

        [Fact]
        public void PostJson_encodes_json()
        {
            InRequest(
                rest => rest.PostJson(Url, new Dictionary<string, object>() { { "k", "v" } }),
                request => {
                    Assert.Equal("{\"k\":\"v\"}",
                                 request.Content.ReadAsStringAsync().Result);
                });
        }

        [Fact]
        public void PostForm_sends_form_headers()
        {
            InRequest(
                rest => rest.PostForm(Url, new Dictionary<string, object>()),
                request => {
                    Assert.Equal(new[] { "application/x-www-form-urlencoded" },
                                 request.Content.Headers.GetValues("Content-type"));
                });
        }

        [Fact]
        public void PostJson_encodes_form()
        {
            InRequest(
                rest => rest.PostForm(Url, new Dictionary<string, object>() { { "k", "v" } }),
                request => {
                    Assert.Equal("k=v",
                                 request.Content.ReadAsStringAsync().Result);
                });
        }

        [Fact]
        public void MakeAbsoluteUri_joins_url_with_slashes()
        {
            string[] bases = { "http://all.your.base", "http://all.your.base/" };
            string[] endpoints = { "are/belong/to/us", "/are/belong/to/us" };

            foreach (var b in bases)
            {
                RestClient rest = new RestClient(null, b);
                foreach (var e in endpoints)
                    Assert.Equal("http://all.your.base/are/belong/to/us", rest.MakeAbsoluteUri(e).AbsoluteUri);
            }
        }

        [Fact]
        public void MakeAbsoluteUri_allows_empty_base()
        {
            RestClient rest = new RestClient(null, "");
            Assert.Equal("http://all.your.base/are/belong/to/us",
                         rest.MakeAbsoluteUri("http://all.your.base/are/belong/to/us").AbsoluteUri);
        }

        [Fact]
        public void MakeAbsoluteUri_allows_empty_endpoint()
        {
            var rest = new RestClient(null, "http://all.your.base/are/belong/to/us");
            Assert.Equal("http://all.your.base/are/belong/to/us", rest.MakeAbsoluteUri("").AbsoluteUri);
        }

        [Fact]
        public void MakeAbsoluteUri_throws_on_invalid_format()
        {
            var rest = new RestClient(null, "not an url");
            Assert.Throws<UriFormatException>(() => rest.MakeAbsoluteUri("not an endpoint"));
        }

        //
        // Helpers
        //

        // This is for asserting inside a request like this:
        // InRequest(
        //     rest => rest.Get(url),                    // <- perform a rest call
        //     "<html><head>...",                        // <- respond with this content
        //     req => Assert.Equal(url, req.RequestUri)  // <- verify that the request is as expected
        // );
        internal static void InRequest(Action<RestClient> restCall,
                                       string responseContent,
                                       Action<HttpRequestMessage> assertRequest)
        {
            using (var transport = new RestTransport(request => {
                assertRequest(request);
                return RespondWith(responseContent)(request);
            }))
            {
                restCall(new RestClient(transport));
            }
        }

        internal static void InRequest(Action<RestClient> restCall, Action<HttpRequestMessage> assertRequest)
        {
            InRequest(restCall, "", assertRequest);
        }

        internal static RestClient Serve(string response, string baseUrl = "")
        {
            return new RestClient(new RestTransport(RespondWith(response)), baseUrl);
        }

        internal static RestClient Fail(HttpStatusCode status, string baseUrl = "")
        {
            return new RestClient(new RestTransport(RespondWith("", status)), baseUrl);
        }

        private static SendAsyncType RespondWith(string response, HttpStatusCode status = HttpStatusCode.OK)
        {
            return (request) => Task.FromResult(new HttpResponseMessage(status)
            {
                Content = new StringContent(response),
                RequestMessage = request,
            });
        }

        //
        // Data
        //

        private const string Url = "https://example.com/";
    }
}
