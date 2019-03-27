// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Linq;
using System.Net;
using Moq;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using PasswordManagerAccess.Common;
using Xunit;

namespace PasswordManagerAccess.Test.Common
{
    public class JsonHttpClientTest
    {
        [Fact]
        public void Get_makes_GET_request_with_headers()
        {
            var http = SetupGet();
            var client = SetupClient(http);
            var response = client.Get(Endpoint);

            http.Verify(x => x.Get(It.Is<string>(s => s == Url),
                                   It.Is<Dictionary<string, string>>(d => AreEqual(d, Headers))));

            Assert.True(JToken.DeepEquals(response, ResponseJson));
        }

        [Fact]
        public void Get_returns_deserialized_object()
        {
            var http = SetupGet();
            var client = SetupClient(http);
            var response = client.Get<ResponseObject>(Endpoint);

            Assert.Equal("Ok", response.Status);
        }

        [Fact]
        public void Get_throws_on_missing_fields_in_json()
        {
            var http = SetupGet("{}");
            var client = SetupClient(http);

            Exceptions.AssertThrowsInternalError(() => client.Get<ResponseObject>(Endpoint));
        }

        [Fact]
        public void Post_makes_POST_request_with_data_and_headers()
        {
            var http = SetupPost();
            var data = new Dictionary<string, object>
            {
                {"one", "1"},
                {"two", 2},
                {"three", new object[] {"1", 2, true}},
            };
            var encodedData = "{'one':'1','two':2,'three':['1',2,true]}".Replace('\'', '"');

            var client = SetupClient(http);
            var response = client.Post(Endpoint, data);

            http.Verify(x => x.Post(It.Is<string>(s => s == Url),
                                    It.Is<string>(s => s == encodedData),
                                    It.Is<Dictionary<string, string>>(d => AreEqual(d, JsonHeaders))));

            Assert.True(JToken.DeepEquals(response, ResponseJson));
        }

        [Fact]
        public void PostForm_makes_POST_request_with_data_and_headers()
        {
            var http = SetupPost();
            var data = new Dictionary<string, object>
            {
                {"one", "1"},
                {"two", 2},
                {"three", "three"},
            };
            var encodedData = "one=1&two=2&three=three";

            var client = SetupClient(http);
            var response = client.PostForm(Endpoint, data);

            http.Verify(x => x.Post(It.Is<string>(s => s == Url),
                                    It.Is<string>(s => s == encodedData),
                                    It.Is<Dictionary<string, string>>(d => AreEqual(d, FormHeaders))));

            Assert.True(JToken.DeepEquals(response, ResponseJson));
        }

        [Fact]
        public void Post_returns_deserialized_object()
        {
            var http = SetupPost();
            var client = SetupClient(http);
            var response = client.Post<ResponseObject>(Endpoint, new Dictionary<string, object>());

            Assert.Equal("Ok", response.Status);
        }

        [Fact]
        public void Post_throws_on_missing_fields_in_json()
        {
            var http = SetupPost("{}");
            var client = SetupClient(http);

            Exceptions.AssertThrowsInternalError(
                () => client.Post<ResponseObject>(Endpoint, new Dictionary<string, object>()));
        }

        [Fact]
        public void MakeUrl_joins_url_with_slashes()
        {
            string[] bases = {"http://all.your.base", "http://all.your.base/"};
            string[] endpoints = {"are/belong/to/us", "/are/belong/to/us"};

            foreach (var b in bases)
                foreach (var e in endpoints)
                    Assert.Equal("http://all.your.base/are/belong/to/us", new JsonHttpClient(null, b).MakeUrl(e));
        }

        [Fact]
        public void UrlEncode_returns_encoded_parameters()
        {
            var encoded = JsonHttpClient.UrlEncode(new Dictionary<string, object>
            {
                {"1", 2},
                {"three", "four"},
                {"white space", "and symbols @%!/$"},
            });

            Assert.Equal("1=2&three=four&white+space=and+symbols+%40%25!%2F%24", encoded);
        }

        //
        // Helper
        //

        private const string BaseUrl = "https://whats.up";
        private const string Endpoint = "one/two/three";
        private const string Url = "https://whats.up/one/two/three";

        [JsonObject(ItemRequired = Required.Always)]
        public struct ResponseObject
        {
            public string Status;
        }

        private const string Response = "{'Status': 'Ok'}";
        private static readonly JObject ResponseJson = JObject.Parse(Response);

        private static readonly Dictionary<string, string> Headers = new Dictionary<string, string>()
        {
            {"Accept", "application/json"},
            {"Content-Type", "Should be overwritten"},
            {"Header1", "Blah-blah"},
            {"Header2", "Blah-blah-blah"},
            {"Header3", "Blah-blah-blah-blah, blah, blah!"},
        };

        private static readonly Dictionary<string, string> JsonHeaders = new Dictionary<string, string>()
        {
            {"Accept", "application/json"},
            {"Content-Type", "application/json; charset=UTF-8"},
            {"Header1", "Blah-blah"},
            {"Header2", "Blah-blah-blah"},
            {"Header3", "Blah-blah-blah-blah, blah, blah!"},
        };

        private static readonly Dictionary<string, string> FormHeaders = new Dictionary<string, string>()
        {
            {"Accept", "application/json"},
            {"Content-Type", "application/x-www-form-urlencoded; charset=UTF-8"},
            {"Header1", "Blah-blah"},
            {"Header2", "Blah-blah-blah"},
            {"Header3", "Blah-blah-blah-blah, blah, blah!"},
        };

        //
        // Public helpers
        //

        //
        // - GET
        //

        // TODO: Remove copy paste and factor out network testing helpers
        public static Mock<IHttpClient> SetupGet(string response = Response)
        {
            var mock = new Mock<IHttpClient>();
            mock.Setup(x => x.Get(It.IsAny<string>(),
                                  It.IsAny<Dictionary<string, string>>()))
                .Returns(response);
            return mock;
        }

        public static Mock<IHttpClient> SetupGetWithFailure()
        {
            var mock = new Mock<IHttpClient>();
            mock.Setup(x => x.Get(It.IsAny<string>(), It.IsAny<Dictionary<string, string>>()))
                .Throws<WebException>();
            return mock;
        }

        // TODO: internal in inconsistent with public everywhere else
        internal static void VerifyGetUrl(JsonHttpClient http, string url)
        {
            VerifyGetUrl(http.Http, url);
        }

        internal static void VerifyGetUrl(IHttpClient http, string url)
        {
            Mock.Get(http).Verify(x => x.Get(It.Is<string>(s => s.Contains(url)),
                                             It.IsAny<Dictionary<string, string>>()));
        }

        //
        // - POST
        //

        public static Mock<IHttpClient> SetupPost(string response = Response)
        {
            var mock = new Mock<IHttpClient>();
            mock.Setup(x => x.Post(It.IsAny<string>(),
                                   It.IsAny<string>(),
                                   It.IsAny<Dictionary<string, string>>()))
                .Returns(response);
            return mock;
        }

        public static Mock<IHttpClient> SetupPostWithFailure()
        {
            var mock = new Mock<IHttpClient>();
            mock.Setup(x => x.Post(It.IsAny<string>(),
                                   It.IsAny<string>(),
                                   It.IsAny<Dictionary<string, string>>()))
                .Throws<WebException>();
            return mock;
        }

        // TODO: internal in inconsistent with public everywhere else
        internal static void VerifyPostUrl(JsonHttpClient http, string url)
        {
            VerifyPostUrl(http.Http, url);
        }

        internal static void VerifyPostUrl(IHttpClient http, string url)
        {
            Mock.Get(http).Verify(x => x.Post(It.Is<string>(s => s.Contains(url)),
                                              It.IsAny<string>(),
                                              It.IsAny<Dictionary<string, string>>()));
        }

        //
        // Private
        //

        private static JsonHttpClient SetupClient(Mock<IHttpClient> http)
        {
            return new JsonHttpClient(http.Object, BaseUrl, Headers);
        }

        private static bool AreEqual<TK, TV>(Dictionary<TK, TV> a, Dictionary<TK, TV> b)
        {
            return a.OrderBy(i => i.Key).SequenceEqual(b.OrderBy(i => i.Key));
        }
    }
}
