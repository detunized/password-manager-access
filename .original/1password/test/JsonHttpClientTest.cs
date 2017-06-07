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

            Assert.That(JToken.DeepEquals(response, GetResponseJson));
        }

        [Test]
        public void Get_makes_GET_request_with_join_url_and_headers()
        {
            var http = SetupGet();
            var response = new JsonHttpClient(http.Object).Get(UrlComponents, Headers);

            http.Verify(x => x.Get(It.Is<string>(s => s == Url),
                                   It.Is<Dictionary<string, string>>(d => AreEqual(d, Headers))));

            Assert.That(JToken.DeepEquals(response, GetResponseJson));
        }

        //
        // Helper
        //

        private const string Url = "https://whats.up/one/two/three";
        private static readonly string[] UrlComponents = {"https://whats.up", "one", "two", "three"};

        private const string GetResponse = "{'status': 'ok'}";
        private static readonly JObject GetResponseJson = JObject.Parse(GetResponse);

        private static readonly Dictionary<string, string> Headers = new Dictionary<string, string>()
        {
            {"Header1", "Blah-blah"},
            {"Header2", "Blah-blah-blah"},
            {"Header3", "Blah-blah-blah-blah, blah, blah!"},
        };

        private Mock<IHttpClient> SetupGet(string response = GetResponse)
        {
            var mock = new Mock<IHttpClient>();
            mock.Setup(x => x.Get(It.IsAny<string>(),
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
