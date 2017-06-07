// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Linq;
using Moq;
using Newtonsoft.Json.Linq;
using NUnit.Framework;

namespace OnePassword.Test
{
    [TestFixture]
    public class JsonHttpClientTest
    {
        [Test]
        public void Get_makes_GET_request_with_headers()
        {
            var http = SetupGet();
            var response = new JsonHttpClient(http.Object).Get(Url, Headers);

            http.Verify(x => x.Get(It.Is<string>(s => s == Url),
                                   It.Is<Dictionary<string, string>>(d => AreEqual(d, Headers))));

            Assert.That(JToken.DeepEquals(response, ResponseJson));
        }

        [Test]
        public void Get_makes_GET_request_with_join_url_and_headers()
        {
            var http = SetupGet();
            var response = new JsonHttpClient(http.Object).Get(UrlComponents, Headers);

            http.Verify(x => x.Get(It.Is<string>(s => s == Url),
                                   It.Is<Dictionary<string, string>>(d => AreEqual(d, Headers))));

            Assert.That(JToken.DeepEquals(response, ResponseJson));
        }

        [Test]
        public void Post_makes_POST_request_with_data_and_headers()
        {
            var http = SetupPost();
            var data = new Dictionary<string, object>
            {
                {"number", 13},
                {"string", "hi"},
                {"array", new object[] {null, 1.0, 2, "three"}},
                {"object", new Dictionary<string, object>{{"a", 1}, {"b", "two"}}},
            };
            var encodedData = "{'number':13,'string':'hi','array':[null,1.0,2,'three'],'object':{'a':1,'b':'two'}}"
                .Replace('\'', '"');

            var response = new JsonHttpClient(http.Object).Post(Url, data, Headers);

            http.Verify(x => x.Post(It.Is<string>(s => s == Url),
                                    It.Is<string>(s => s == encodedData),
                                    It.Is<Dictionary<string, string>>(d => AreEqual(d, JsonHeaders))));

            Assert.That(JToken.DeepEquals(response, ResponseJson));
        }

        //
        // Helper
        //

        private const string Url = "https://whats.up/one/two/three";
        private static readonly string[] UrlComponents = {"https://whats.up", "one", "two", "three"};

        private const string Response = "{'status': 'ok'}";
        private static readonly JObject ResponseJson = JObject.Parse(Response);

        private static readonly Dictionary<string, string> Headers = new Dictionary<string, string>()
        {
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

        private Mock<IHttpClient> SetupGet(string response = Response)
        {
            var mock = new Mock<IHttpClient>();
            mock.Setup(x => x.Get(It.IsAny<string>(),
                                  It.IsAny<Dictionary<string, string>>()))
                .Returns(response);
            return mock;
        }

        private Mock<IHttpClient> SetupPost(string response = Response)
        {
            var mock = new Mock<IHttpClient>();
            mock.Setup(x => x.Post(It.IsAny<string>(),
                                   It.IsAny<string>(),
                                   It.IsAny<Dictionary<string, string>>()))
                .Returns(response);
            return mock;
        }

        private static bool AreEqual<TK, TV>(Dictionary<TK, TV> a, Dictionary<TK, TV> b)
        {
            return a.OrderBy(i => i.Key).SequenceEqual(b.OrderBy(i => i.Key));
        }
    }
}
