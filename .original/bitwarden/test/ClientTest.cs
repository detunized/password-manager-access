// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using Moq;
using Newtonsoft.Json;
using NUnit.Framework;

namespace Bitwarden.Test
{
    [TestFixture]
    public class ClientTest
    {
        [Test]
        public void RequestKdfIterationCount_returns_iteration_count()
        {
            var count = Client.RequestKdfIterationCount(Username, SetupKdfRequest());

            Assert.That(count, Is.EqualTo(1337));
        }

        [Test]
        public void RequestKdfIterationCount_makes_POST_request_to_specific_endpoint()
        {
            var jsonHttp = SetupKdfRequest();
            Client.RequestKdfIterationCount(Username, jsonHttp);

            JsonHttpClientTest.VerifyPostUrl(jsonHttp.Http, ".com/api/accounts/prelogin");
        }

        [Test]
        public void RequestAuthToken_returns_auth_token()
        {
            var token = Client.RequestAuthToken(Username, PasswordHash, SetupAuthTokenRequest());

            Assert.That(token, Is.EqualTo("Bearer wa-wa-wee-wa"));
        }

        [Test]
        public void RequestAuthToken_makes_POST_request_to_specific_endpoint()
        {
            var jsonHttp = SetupAuthTokenRequest();
            Client.RequestAuthToken(Username, PasswordHash, jsonHttp);

            JsonHttpClientTest.VerifyPostUrl(jsonHttp.Http, ".com/identity/connect/token");
        }

        [Test]
        public void DecryptVault_returns_accounts()
        {
            var key = "SLBgfXoityZsz4ZWvpEPULPZMYGH6vSqh3PXTe5DmyM=".Decode64();
            var vault = JsonConvert.DeserializeObject<Response.Vault>(JsonHttpClientTest.ReadFixture("vault"));
            var accounts = Client.DecryptVault(vault, key);

            Assert.That(accounts.Length, Is.EqualTo(2));
            Assert.That(accounts[0].Name, Is.EqualTo("Facebook"));
            Assert.That(accounts[1].Name, Is.EqualTo("Google"));
        }

        //
        // Helpers
        //

        private static JsonHttpClient SetupKdfRequest()
        {
            return SetupPost("{'Kdf': 0, 'KdfIterations': 1337}");
        }

        private static JsonHttpClient SetupAuthTokenRequest()
        {
            return SetupPost("{'token_type': 'Bearer', 'access_token': 'wa-wa-wee-wa'}");
        }

        private static JsonHttpClient SetupPost(string response)
        {
            return MakeJsonHttp(JsonHttpClientTest.SetupPost(response));
        }

        private static JsonHttpClient MakeJsonHttp(Mock<IHttpClient> http)
        {
            return new JsonHttpClient(http.Object, "https://vault.bitwarden.com");
        }

        //
        // Data
        //

        private const string Username = "username";
        private static readonly byte[] PasswordHash = "password-hash".ToBytes();
    }
}
