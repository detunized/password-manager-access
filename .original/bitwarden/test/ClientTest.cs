// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using Moq;
using NUnit.Framework;

namespace Bitwarden.Test
{
    [TestFixture]
    public class ClientTest
    {
        [Test]
        public void RequestKdfIterationCount_returns_iteration_count()
        {
            var count = Client.RequestKdfIterationCount("username", SetupKdfRequest());

            Assert.That(count, Is.EqualTo(1337));
        }

        [Test]
        public void RequestKdfIterationCount_makes_POST_request_to_specific_endpoint()
        {
            var jsonHttp = SetupKdfRequest();
            Client.RequestKdfIterationCount("username", jsonHttp);

            JsonHttpClientTest.VerifyPostUrl(jsonHttp.Http, ".com/api/accounts/prelogin");
        }

        //
        // Helpers
        //

        private static JsonHttpClient SetupKdfRequest()
        {
            return MakeJsonHttp(JsonHttpClientTest.SetupPost("{'Kdf': 0, 'KdfIterations': 1337}".Replace('\'', '"')));
        }

        private static JsonHttpClient MakeJsonHttp(Mock<IHttpClient> http)
        {
            return new JsonHttpClient(http.Object, "https://vault.bitwarden.com");
        }
    }
}
