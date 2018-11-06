// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using Moq;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using NUnit.Framework;

namespace Bitwarden.Test
{
    [TestFixture]
    public class JsonHttpClientTest
    {
        [Test]
        public void Get_makes_GET_request_with_headers()
        {
            var http = SetupGet();
            var client = SetupClient(http);
            var response = client.Get(Endpoint);

            http.Verify(x => x.Get(It.Is<string>(s => s == Url),
                                   It.Is<Dictionary<string, string>>(d => AreEqual(d, Headers))));

            Assert.That(JToken.DeepEquals(response, ResponseJson));
        }

        [Test]
        public void Get_returns_deserialized_object()
        {
            var http = SetupGet();
            var client = SetupClient(http);
            var response = client.Get<ResponseObject>(Endpoint);

            Assert.That(response.Status, Is.EqualTo("Ok"));
        }

        [Test]
        public void Get_throws_on_missing_fields_in_json()
        {
            var http = SetupGet("{}");
            var client = SetupClient(http);

            Assert.That(() => client.Get<ResponseObject>(Endpoint),
                        Throws.InstanceOf<ClientException>()
                            .And.Property("Reason")
                            .EqualTo(ClientException.FailureReason.InvalidResponse));
        }

        [Test]
        public void Post_makes_POST_request_with_data_and_headers()
        {
            var http = SetupPost();
            var data = new Dictionary<string, string>
            {
                {"one", "1"},
                {"two", "2"},
                {"three", "3"},
            };
            var encodedData = "{'one':'1','two':'2','three':'3'}".Replace('\'', '"');

            var client = SetupClient(http);
            var response = client.Post(Endpoint, data);

            http.Verify(x => x.Post(It.Is<string>(s => s == Url),
                                    It.Is<string>(s => s == encodedData),
                                    It.Is<Dictionary<string, string>>(d => AreEqual(d, JsonHeaders))));

            Assert.That(JToken.DeepEquals(response, ResponseJson));
        }

        [Test]
        public void PostForm_makes_POST_request_with_data_and_headers()
        {
            var http = SetupPost();
            var data = new Dictionary<string, string>
            {
                {"one", "1"},
                {"two", "2"},
                {"three", "3"},
            };
            var encodedData = "one=1&two=2&three=3";

            var client = SetupClient(http);
            var response = client.PostForm(Endpoint, data);

            http.Verify(x => x.Post(It.Is<string>(s => s == Url),
                                    It.Is<string>(s => s == encodedData),
                                    It.Is<Dictionary<string, string>>(d => AreEqual(d, FormHeaders))));

            Assert.That(JToken.DeepEquals(response, ResponseJson));
        }

        [Test]
        public void Post_returns_deserialized_object()
        {
            var http = SetupPost();
            var client = SetupClient(http);
            var response = client.Post<ResponseObject>(Endpoint, new Dictionary<string, string>());

            Assert.That(response.Status, Is.EqualTo("Ok"));
        }

        [Test]
        public void Post_throws_on_missing_fields_in_json()
        {
            var http = SetupPost("{}");
            var client = SetupClient(http);

            Assert.That(() => client.Post<ResponseObject>(Endpoint, new Dictionary<string, string>()),
                        Throws.InstanceOf<ClientException>()
                            .And.Property("Reason")
                            .EqualTo(ClientException.FailureReason.InvalidResponse));
        }

        [Test]
        public void MakeUrl_joins_url_with_slashes()
        {
            string[] bases = {"http://all.your.base", "http://all.your.base/"};
            string[] endpoints = {"are/belong/to/us", "/are/belong/to/us"};

            foreach (var b in bases)
                foreach (var e in endpoints)
                    Assert.That(new JsonHttpClient(null, b).MakeUrl(e),
                                Is.EqualTo("http://all.your.base/are/belong/to/us"));
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
            {"Content-Type", "Should be overwritten"},
            {"Header1", "Blah-blah"},
            {"Header2", "Blah-blah-blah"},
            {"Header3", "Blah-blah-blah-blah, blah, blah!"},
        };

        private static readonly Dictionary<string, string> JsonHeaders = new Dictionary<string, string>()
        {
            {"Content-Type", "application/json; charset=UTF-8"},
            {"Header1", "Blah-blah"},
            {"Header2", "Blah-blah-blah"},
            {"Header3", "Blah-blah-blah-blah, blah, blah!"},
        };

        private static readonly Dictionary<string, string> FormHeaders = new Dictionary<string, string>()
        {
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

        public static Mock<IHttpClient> SetupGetWithFixture(string name)
        {
            return SetupGet(ReadFixture(name));
        }

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

        public static void VerifyGetUrl(IHttpClient http, string url)
        {
            Mock.Get(http).Verify(x => x.Get(It.Is<string>(s => s.Contains(url)),
                                             It.IsAny<Dictionary<string, string>>()));
        }

        //
        // - POST
        //

        public static Mock<IHttpClient> SetupPostWithFixture(string name)
        {
            return SetupPost(ReadFixture(name));
        }

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

        public static void VerifyPostUrl(IHttpClient http, string url)
        {
            Mock.Get(http).Verify(x => x.Post(It.Is<string>(s => s.Contains(url)),
                                              It.IsAny<string>(),
                                              It.IsAny<Dictionary<string, string>>()));
        }

        public static string ReadFixture(string name)
        {
            return File.ReadAllText(string.Format("Fixtures/{0}.json", name));
        }

        //
        // Private
        //

        private static JsonHttpClient SetupClient(Mock<IHttpClient> http)
        {
            return new JsonHttpClient(http.Object, BaseUrl) {Headers = Headers};
        }

        private static bool AreEqual<TK, TV>(Dictionary<TK, TV> a, Dictionary<TK, TV> b)
        {
            return a.OrderBy(i => i.Key).SequenceEqual(b.OrderBy(i => i.Key));
        }
    }
}
