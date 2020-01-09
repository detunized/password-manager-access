// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using PasswordManagerAccess.Common;
using Xunit;

namespace PasswordManagerAccess.Test.Common
{
    using SendAsyncType = Func<HttpRequestMessage, Task<HttpResponseMessage>>;

    // TODO: Test redirects
    public class RestClientTest
    {
        //
        // GET
        //

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
                rest => rest.Get(Url, headers: TestHeaders),
                request =>
                {
                    Assert.Equal(new[] { TestHeaderValue }, request.Headers.GetValues(TestHeaderName));
                });
        }

        [Fact]
        public void Get_sends_cookies()
        {
            InRequest(
                rest => rest.Get(Url, cookies: TestCookies),
                request =>
                {
                    Assert.Equal(new[] { TestCookieHeader }, request.Headers.GetValues("Cookie"));
                });
        }

        [Fact]
        public void Get_decodes_json()
        {
            var response = Serve("{'Key': 'k', 'Value': 'v'}").Get<KeyValuePair<string, string>>(Url);

            Assert.True(response.IsSuccessful);
            Assert.Equal(new KeyValuePair<string, string>("k", "v"), response.Data);
        }

        //
        // POST JSON/form
        //

        [Fact]
        public void PostJson_sends_json_headers()
        {
            InRequest(
                rest => rest.PostJson(Url, NoParameters),
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
                rest => rest.PostForm(Url, NoParameters),
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
        // PUT
        //

        [Fact]
        public void Put_works()
        {
            var response = Serve("yo").Put(Url);

            Assert.True(response.IsSuccessful);
            Assert.Equal("yo", response.Content);
        }

        [Fact]
        public void Put_sets_url()
        {
            InRequest(
                rest => rest.Put(Url),
                request => Assert.Equal(Url, request.RequestUri.AbsoluteUri));
        }

        [Fact]
        public void Put_sends_headers()
        {
            InRequest(
                rest => rest.Put(Url, headers: TestHeaders),
                request => Assert.Equal(new[] { TestHeaderValue }, request.Headers.GetValues(TestHeaderName)));
        }

        [Fact]
        public void Put_sends_cookies()
        {
            InRequest(
                rest => rest.Put(Url, cookies: TestCookies),
                request => Assert.Equal(new[] { TestCookieHeader }, request.Headers.GetValues("Cookie")));
        }

        [Fact]
        public void Put_decodes_json()
        {
            var response = Serve("{'Key': 'k', 'Value': 'v'}").Put<KeyValuePair<string, string>>(Url);

            Assert.True(response.IsSuccessful);
            Assert.Equal(new KeyValuePair<string, string>("k", "v"), response.Data);
        }

        //
        // URI
        //

        [Theory]
        // Only domain
        [InlineData("http://all.your.base", "are/belong/to/us")]
        [InlineData("http://all.your.base", "/are/belong/to/us")]
        [InlineData("http://all.your.base/", "are/belong/to/us")]
        [InlineData("http://all.your.base/", "/are/belong/to/us")]
        // Domain with path
        [InlineData("http://all.your.base/are", "belong/to/us")]
        [InlineData("http://all.your.base/are", "/belong/to/us")]
        [InlineData("http://all.your.base/are/", "belong/to/us")]
        [InlineData("http://all.your.base/are/", "/belong/to/us")]
        public void MakeAbsoluteUri_joins_url_with_slashes(string baseUrl, string endpoint)
        {
            var rest = new RestClient(null, baseUrl);
            Assert.Equal("http://all.your.base/are/belong/to/us", rest.MakeAbsoluteUri(endpoint).AbsoluteUri);
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
        // Request signer
        //

        // Here we test every request type (GET, POST, PUT) only once to make sure all requests are
        // going through a signer. Other signer features we test only on GET to make things brief.

        [Fact]
        public void Get_request_is_signed_with_extra_headers()
        {
            InRequest(
                rest => rest.Get(Url, headers: TestHeaders),
                new AppendSigner(),
                request => {
                    Assert.Equal(new[] { TestHeaderValue }, request.Headers.GetValues(TestHeaderName));
                    Assert.Equal(new[] { Url }, request.Headers.GetValues("TestSigner-uri"));
                    Assert.Equal(new[] { "GET" }, request.Headers.GetValues("TestSigner-method"));
                    Assert.Equal(new[] { "extra" }, request.Headers.GetValues("TestSigner-extra"));
                });
        }

        [Fact]
        public void Post_request_is_signed_with_extra_headers()
        {
            InRequest(
                rest => rest.PostJson(Url, NoParameters, TestHeaders),
                new AppendSigner(),
                request => {
                    Assert.Equal(new[] { TestHeaderValue }, request.Headers.GetValues(TestHeaderName));
                    Assert.Equal(new[] { Url }, request.Headers.GetValues("TestSigner-uri"));
                    Assert.Equal(new[] { "POST" }, request.Headers.GetValues("TestSigner-method"));
                    Assert.Equal(new[] { "extra" }, request.Headers.GetValues("TestSigner-extra"));
                });
        }

        [Fact]
        public void Put_request_is_signed_with_extra_headers()
        {
            InRequest(
                rest => rest.Put(Url, headers: TestHeaders),
                new AppendSigner(),
                request => {
                    Assert.Equal(new[] { TestHeaderValue }, request.Headers.GetValues(TestHeaderName));
                    Assert.Equal(new[] { Url }, request.Headers.GetValues("TestSigner-uri"));
                    Assert.Equal(new[] { "PUT" }, request.Headers.GetValues("TestSigner-method"));
                    Assert.Equal(new[] { "extra" }, request.Headers.GetValues("TestSigner-extra"));
                });
        }

        [Fact]
        public void Signer_can_remove_headers()
        {
            InRequest(
                rest => rest.Get(Url, headers: TestHeaders),
                new RemoveSigner(),
                request => Assert.False(request.Headers.Contains(TestHeaderName)));
        }

        [Fact]
        public void Signer_can_modify_headers()
        {
            InRequest(
                rest => rest.Get(Url, headers: TestHeaders),
                new ModifySigner(),
                request => Assert.Equal(new[] { TestHeaderValue + "-modified" },
                                        request.Headers.GetValues(TestHeaderName)));
        }

        [Fact]
        public void Get_sends_default_headers()
        {
            InRequest(
                rest => rest.Get(Url),
                "",
                NoSigner,
                TestHeaders,
                NoCookies,
                request => Assert.Equal(new[] { TestHeaderValue }, request.Headers.GetValues(TestHeaderName)));
        }

        [Fact]
        public void Get_sends_default_cookies()
        {
            InRequest(
                rest => rest.Get(Url),
                "",
                NoSigner,
                NoHeaders,
                TestCookies,
                request => Assert.Equal(new[] { TestCookieHeader }, request.Headers.GetValues("Cookie")));
        }

        [Fact]
        public void Post_sends_default_headers()
        {
            InRequest(
                rest => rest.PostJson(Url, NoParameters),
                "",
                NoSigner,
                TestHeaders,
                NoCookies,
                request => Assert.Equal(new[] { TestHeaderValue }, request.Headers.GetValues(TestHeaderName)));
        }

        [Fact]
        public void Post_sends_default_cookies()
        {
            InRequest(
                rest => rest.PostJson(Url, NoParameters),
                "",
                NoSigner,
                NoHeaders,
                TestCookies,
                request => Assert.Equal(new[] { TestCookieHeader }, request.Headers.GetValues("Cookie")));
        }

        [Fact]
        public void Put_sends_default_headers()
        {
            InRequest(
                rest => rest.Put(Url),
                "",
                NoSigner,
                TestHeaders,
                NoCookies,
                request => Assert.Equal(new[] { TestHeaderValue }, request.Headers.GetValues(TestHeaderName)));
        }

        [Fact]
        public void Put_sends_default_cookies()
        {
            InRequest(
                rest => rest.Put(Url),
                "",
                NoSigner,
                NoHeaders,
                TestCookies,
                request => Assert.Equal(new[] { TestCookieHeader }, request.Headers.GetValues("Cookie")));
        }

        [Fact]
        public void Request_headers_override_default_headers()
        {
            InRequest(
                rest => rest.Get(Url, headers: TestHeaders),
                "",
                NoSigner,
                new Dictionary<string, string> { { TestHeaderName, "default-value" } },
                NoCookies,
                request => Assert.Equal(new[] { TestHeaderValue }, request.Headers.GetValues(TestHeaderName)));
        }

        [Fact]
        public void Request_cookies_override_default_cookies()
        {
            InRequest(
                rest => rest.Get(Url, cookies: TestCookies),
                "",
                NoSigner,
                NoHeaders,
                new Dictionary<string, string> { { TestCookieName, "default-value" } },
                request => Assert.Equal(new[] { TestCookieHeader }, request.Headers.GetValues("Cookie")));
        }

        [Fact]
        public void Signer_modifies_default_headers()
        {
            InRequest(
                rest => rest.Get(Url),
                "",
                new ModifySigner(),
                TestHeaders,
                NoCookies,
                request => Assert.Equal(new[] { TestHeaderValue + "-modified" },
                                        request.Headers.GetValues(TestHeaderName)));
        }

        //
        // Helpers
        //

        class AppendSigner : IRequestSigner
        {
            public IReadOnlyDictionary<string, string> Sign(Uri uri, HttpMethod method,
                                                            IReadOnlyDictionary<string, string> headers)
            {
                return headers.Merge(new Dictionary<string, string>
                {
                    { "TestSigner-uri", uri.ToString() },
                    { "TestSigner-method", method.ToString() },
                    { "TestSigner-extra", "extra" },
                });
            }
        }

        class RemoveSigner : IRequestSigner
        {
            public IReadOnlyDictionary<string, string> Sign(Uri uri, HttpMethod method,
                                                            IReadOnlyDictionary<string, string> headers)
            {
                return new Dictionary<string, string>();
            }
        }

        class ModifySigner : IRequestSigner
        {
            public IReadOnlyDictionary<string, string> Sign(Uri uri, HttpMethod method,
                                                            IReadOnlyDictionary<string, string> headers)
            {
                return headers.ToDictionary(x => x.Key, x => x.Value + "-modified");
            }
        }

        // This is for asserting inside a request like this:
        // InRequest(
        //     rest => rest.Get(url),                    // <- perform a rest call
        //     "<html><head>...",                        // <- respond with this content
        //     req => Assert.Equal(url, req.RequestUri)  // <- verify that the request is as expected
        // );
        internal static void InRequest(Action<RestClient> restCall,
                                       string responseContent,
                                       IRequestSigner signer,
                                       IReadOnlyDictionary<string, string> defaultHeaders,
                                       IReadOnlyDictionary<string, string> defaultCookies,
                                       Action<HttpRequestMessage> assertRequest)
        {
            using (var transport = new RestTransport(request => {
                assertRequest(request);
                return RespondWith(responseContent)(request);
            }))
            {
                restCall(new RestClient(transport, "", signer, defaultHeaders, defaultCookies));
            }
        }

        internal static void InRequest(Action<RestClient> restCall,
                                       IRequestSigner signer,
                                       Action<HttpRequestMessage> assertRequest)
        {
            InRequest(restCall, "", signer, NoHeaders, NoCookies, assertRequest);
        }

        internal static void InRequest(Action<RestClient> restCall, Action<HttpRequestMessage> assertRequest)
        {
            InRequest(restCall, NoSigner, assertRequest);
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
        private static readonly Dictionary<string, object> NoParameters = new Dictionary<string, object>();
        private static readonly IRequestSigner NoSigner = null;
        private static readonly IReadOnlyDictionary<string, string> NoHeaders = new Dictionary<string, string>();
        private static readonly IReadOnlyDictionary<string, string> NoCookies = new Dictionary<string, string>();

        private const string TestHeaderName = "header-name";
        private const string TestHeaderValue = "header-value";
        private static readonly Dictionary<string, string> TestHeaders = new Dictionary<string, string>
        {
            { TestHeaderName, TestHeaderValue }
        };

        private const string TestCookieName = "cookie-name";
        private const string TestCookieValue = "cookie-value";
        private static readonly string TestCookieHeader = $"{TestCookieName}={TestCookieValue}";
        private static readonly Dictionary<string, string> TestCookies = new Dictionary<string, string>
        {
            { TestCookieName, TestCookieValue }
        };
    }
}
