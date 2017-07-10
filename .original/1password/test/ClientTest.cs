// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using Moq;
using NUnit.Framework;

namespace OnePassword.Test
{
    [TestFixture]
    public class ClientTest
    {
        [Test]
        public void StartNewSession_returns_session_on_ok()
        {
            var http = MakeJsonHttp(JsonHttpClientTest.SetupGetWithFixture("start-new-session-response"));
            var session = Client.StartNewSession(TestData.ClientInfo, http);

            Assert.That(session.Id, Is.EqualTo(TestData.Session.Id));
            Assert.That(session.KeyFormat, Is.EqualTo(TestData.Session.KeyFormat));
            Assert.That(session.KeyUuid, Is.EqualTo(TestData.Session.KeyUuid));
            Assert.That(session.SrpMethod, Is.EqualTo(TestData.Session.SrpMethod));
            Assert.That(session.KeyMethod, Is.EqualTo(TestData.Session.KeyMethod));
            Assert.That(session.Iterations, Is.EqualTo(TestData.Session.Iterations));
            Assert.That(session.Salt, Is.EqualTo(TestData.Session.Salt));
        }

        [Test]
        public void StartNewSession_throws_on_unknown_status()
        {
            var http = MakeJsonHttp(JsonHttpClientTest.SetupGet("{'status': 'unknown'}"));
            Assert.That(() => Client.StartNewSession(TestData.ClientInfo, http),
                        Throws.TypeOf<InvalidOperationException>()
                            .And.Message.StartsWith("Failed to start a new session")
                            .And.Message.Contains("'unknown'"));
        }

        [Test]
        public void VerifySessionKey_works()
        {
            var http = MakeJsonHttp(JsonHttpClientTest.SetupPostWithFixture("verify-key-response"));
            Client.VerifySessionKey(TestData.Session, TestData.SesionKey, http);
        }

        [Test]
        public void GetAccountInfo_works()
        {
            var http =
                MakeJsonHttp(JsonHttpClientTest.SetupGetWithFixture("get-account-info-response"));
            Client.GetAccountInfo(TestData.SesionKey, http);
        }

        [Test]
        public void GetVaultAccounts_work()
        {
            var http =
                MakeJsonHttp(
                    JsonHttpClientTest.SetupGetWithFixture("get-vault-accounts-ru74-response"));
            var keychain = new Keychain();
            keychain.Add(new AesKey("x4ouqoqyhcnqojrgubso4hsdga",
                                    "ce92c6d1af345c645211ad49692b22338d128d974e3b6718c868e02776c873a9".DecodeHex()));

            Client.GetVaultAccounts("ru74fjxlkipzzctorwj4icrj2a", TestData.SesionKey, keychain, http);
        }

        [Test]
        public void SignOut_works()
        {
            var http = MakeJsonHttp(JsonHttpClientTest.SetupPut("{'success': 1}"));
            Client.SignOut(http);
        }

        [Test]
        public void SignOut_throws_on_bad_response()
        {
            var http = MakeJsonHttp(JsonHttpClientTest.SetupPut("{'success': 0}"));
            Assert.That(() => Client.SignOut(http), Throws.TypeOf<InvalidOperationException>());
        }

        [Test]
        public void DecryptKeys_stores_keys_in_keychain()
        {
            var http = MakeJsonHttp(JsonHttpClientTest.SetupGetWithFixture("get-account-info-response"));
            var accountInfo = Client.GetAccountInfo(TestData.SesionKey, http);
            var keychain = new Keychain();

            Client.DecryptKeys(accountInfo, ClientInfo, keychain);

            var aesKeys = new[]
            {
                "mp",
                "x4ouqoqyhcnqojrgubso4hsdga",
                "byq5gi5adlasqyy2l2o7iddzvq",
            };

            foreach (var i in aesKeys)
                Assert.That(keychain.GetAes(i), Is.Not.Null);

            var keysets = new[]
            {
                "szerdhg2ww2ahjo4ilz57x7cce",
                "yf2ji37vkqdow7pnbo3y37b3lu",
                "srkx3r5c3qgyzsdswfc4awgh2m",
                "sm5hkw3mxwdcwcgljf4kyplwea",
            };

            foreach (var i in keysets)
            {
                Assert.That(keychain.GetAes(i), Is.Not.Null);
                Assert.That(keychain.GetRsa(i), Is.Not.Null);
            }
        }

        [Test]
        public void DeriveMasterKey_returns_master_key()
        {
            var expected =
                "09f6cf6acc4f64f2ac6af5d912427253c4dd5e1a48dfc6bfea21df8f6d3a701e".DecodeHex();
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

        //
        // Helpers
        //

        private static JsonHttpClient MakeJsonHttp(Mock<IHttpClient> http)
        {
            return new JsonHttpClient(http.Object, Client.ApiUrl);
        }
    }
}
