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

        //
        // Helpers
        //

        // This is for asserting inside a request like this:
        // InRequest(
        //     rest => rest.Get(url),                    // <- perform a rest call
        //     req => Assert.Equal(url, req.RequestUri)  // <- verify that the request is as expected
        // );
        private static void InRequest(Action<RestClient> restCall, Action<HttpRequestMessage> assertRequest)
        {
            restCall(new RestClient(request => {
                assertRequest(request);
                return RespondWith("")(request);
            }));
        }

        private static RestClient Serve(string response)
        {
            return new RestClient(RespondWith(response));
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
