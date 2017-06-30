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
        public void DecryptKeys_stores_keys_in_keychain()
        {
            var http = JsonHttpClientTest.SetupGetWithFixture("get-account-info-response");
            var accountInfo = new Client(http.Object).GetAccountInfo(TestData.SesionKey);
            var keychain = new Keychain();

            Client.DecryptKeysets(accountInfo.At("user/keysets"), ClientInfo, keychain);
            Client.DecryptGroupKeys(accountInfo.At("groups"), keychain);

            Assert.That(keychain.GetAes("mp"), Is.Not.Null);

            var keys = new[]
            {
                "szerdhg2ww2ahjo4ilz57x7cce",
                "yf2ji37vkqdow7pnbo3y37b3lu",
                "srkx3r5c3qgyzsdswfc4awgh2m",
                "sm5hkw3mxwdcwcgljf4kyplwea"
            };

            foreach (var i in keys)
            {
                Assert.That(keychain.GetAes(i), Is.Not.Null);
                Assert.That(keychain.GetRsa(i), Is.Not.Null);
            }
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

        //
        // Data
        //

        // TODO: All the tests here use the data from this account. I don't care about the account
        //       or exposing its credentials, but I don't want to have inconsistent test data.
        //       Everything should be either re-encrypted or somehow harmonized across all the tests
        //       to use the same username, password and account key.
        private static readonly ClientInfo ClientInfo = new ClientInfo(
            username: "detunized@gmail.com",
            password: "Dk%hnM9q2xLY5z6Pe#t&Wutt8L&^W!sz",
            accountKey: "A3-FRN8GF-RBDFX9-6PFY4-6A5E5-457F5-999GY",
            uuid: "rz64r4uhyvgew672nm4ncaqonq");

    }
}
