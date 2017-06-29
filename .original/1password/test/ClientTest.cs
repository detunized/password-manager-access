// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using NUnit.Framework;

namespace OnePassword.Test
{
    [TestFixture]
    public class ClientTest
    {
        [Test]
        public void VerifySessionKey_works()
        {
            var http = JsonHttpClientTest.SetupPostWithFixture("verify-key-response");
            new Client(http.Object).VerifySessionKey(TestData.Session, TestData.SesionKey);
        }

        [Test]
        public void GetAccountInfo_works()
        {
            var http = JsonHttpClientTest.SetupGetWithFixture("get-account-info-response");
            new Client(http.Object).GetAccountInfo(TestData.SesionKey);
        }

        [Test]
        public void DecryptKeysets_works()
        {
            var http = JsonHttpClientTest.SetupGetWithFixture("get-account-info-response");
            var client = new Client(http.Object);
            var accountInfo = client.GetAccountInfo(TestData.SesionKey);

            client.DecryptKeysets(accountInfo.At("user/keysets"), TestData.ClientInfo);
        }

        [Test]
        public void DeriveMasterKey_returns_master_key()
        {
            var expected = "09f6cf6acc4f64f2ac6af5d912427253c4dd5e1a48dfc6bfea21df8f6d3a701e".DecodeHex();
            var key = Client.DeriveMasterKey("PBES2g-HS256",
                                             100000,
                                             "i2enf0xq-XPKCFFf5UZqNQ".Decode64(),
                                             TestData.ClientInfo);

            Assert.That(key.Id, Is.EqualTo("mp"));
            Assert.That(key.Key, Is.EqualTo(expected));
        }
    }
}
