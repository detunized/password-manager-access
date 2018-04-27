// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using Moq;
using Newtonsoft.Json.Linq;
using NUnit.Framework;

// TODO: DRY up tests. There's quite a bit of copy-paste here.

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
        public void StartNewSession_makes_GET_request_to_specific_url()
        {
            var http = MakeJsonHttp(JsonHttpClientTest.SetupGetWithFixture("start-new-session-response"));
            Client.StartNewSession(TestData.ClientInfo, http);

            JsonHttpClientTest.VerifyGetUrl(http.Http, "1password.com/api/v2/auth");
        }

        [Test]
        public void StartNewSession_throws_on_unknown_status()
        {
            var http = MakeJsonHttp(JsonHttpClientTest.SetupGet("{'status': 'unknown'}"));
            Assert.That(() => Client.StartNewSession(TestData.ClientInfo, http),
                        ExceptionsTest.ThrowsInvalidResponseWithMessage("'unknown'")
                            .And.Message.StartsWith("Failed to start a new session"));
        }

        [Test]
        public void StartNewSession_throws_on_network_error()
        {
            var jsonHttp = new JsonHttpClient(JsonHttpClientTest.SetupGetWithFailure().Object, "");

            Assert.That(() => Client.StartNewSession(TestData.ClientInfo, jsonHttp),
                        ExceptionsTest.ThrowsReasonWithMessage(
                            ClientException.FailureReason.NetworkError,
                            "request"));
        }

        [Test]
        public void StartNewSession_throws_on_invalid_json()
        {
            var jsonHttp = new JsonHttpClient(
                JsonHttpClientTest.SetupGet("} invalid json {").Object,
                "");

            Assert.That(() => Client.StartNewSession(TestData.ClientInfo, jsonHttp),
                        ExceptionsTest.ThrowsInvalidResponseWithMessage("Invalid JSON"));
        }

        [Test]
        public void RegisterDevice_works()
        {
            var http = MakeJsonHttp(JsonHttpClientTest.SetupPost("{'success': 1}"));
            Client.RegisterDevice(TestData.ClientInfo, http);
        }

        [Test]
        public void RegisterDevice_makes_POST_request_to_specific_url()
        {
            var http = MakeJsonHttp(JsonHttpClientTest.SetupPost("{'success': 1}"));
            Client.RegisterDevice(TestData.ClientInfo, http);

            JsonHttpClientTest.VerifyPostUrl(http.Http, "1password.com/api/v1/device");
        }

        [Test]
        public void RegisterDevice_throws_on_error()
        {
            var http = MakeJsonHttp(JsonHttpClientTest.SetupPost("{'success': 0}"));
            Assert.That(() => Client.RegisterDevice(TestData.ClientInfo, http),
                        ExceptionsTest.ThrowsRespondedWithErrorWithMessage(TestData.Uuid)
                            .And.Message.StartsWith("Failed to register"));
        }

        [Test]
        public void ReauthorizeDevice_works()
        {
            var http = MakeJsonHttp(JsonHttpClientTest.SetupPut("{'success': 1}"));
            Client.ReauthorizeDevice(TestData.ClientInfo, http);
        }

        [Test]
        public void ReauthorizeDevice_makes_PUT_request_to_specific_url()
        {
            var http = MakeJsonHttp(JsonHttpClientTest.SetupPut("{'success': 1}"));
            Client.ReauthorizeDevice(TestData.ClientInfo, http);

            JsonHttpClientTest.VerifyPutUrl(http.Http, "1password.com/api/v1/device");
        }

        [Test]
        public void ReauthorizeDevice_throws_on_error()
        {
            var http = MakeJsonHttp(JsonHttpClientTest.SetupPut("{'success': 0}"));
            Assert.That(() => Client.ReauthorizeDevice(TestData.ClientInfo, http),
                        ExceptionsTest.ThrowsRespondedWithErrorWithMessage(TestData.Uuid)
                            .And.Message.StartsWith("Failed to reauthorize"));
        }

        [Test]
        public void VerifySessionKey_works()
        {
            var http = MakeJsonHttp(JsonHttpClientTest.SetupPostWithFixture("verify-key-response"));
            Client.VerifySessionKey(TestData.ClientInfo, TestData.Session, TestData.SesionKey, http);
        }

        [Test]
        public void VerifySessionKey_makes_POST_request_to_specific_url()
        {
            var http = MakeJsonHttp(JsonHttpClientTest.SetupPostWithFixture("verify-key-response"));
            Client.VerifySessionKey(TestData.ClientInfo, TestData.Session, TestData.SesionKey, http);

            JsonHttpClientTest.VerifyPostUrl(http.Http, "1password.com/api/v2/auth/verify");
        }

        [Test]
        public void GetAccountInfo_works()
        {
            var http = MakeJsonHttp(JsonHttpClientTest.SetupGetWithFixture("get-account-info-response"));
            Client.GetAccountInfo(TestData.SesionKey, http);
        }

        [Test]
        public void GetAccountInfo_makes_GET_request_to_specific_url()
        {
            var http = MakeJsonHttp(JsonHttpClientTest.SetupGetWithFixture("get-account-info-response"));
            Client.GetAccountInfo(TestData.SesionKey, http);

            JsonHttpClientTest.VerifyGetUrl(http.Http, "1password.com/api/v1/account");
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
        public void GetVaultAccounts_makes_GET_request_to_specific_url()
        {
            var http =
                MakeJsonHttp(
                    JsonHttpClientTest.SetupGetWithFixture("get-vault-accounts-ru74-response"));
            var keychain = new Keychain();
            keychain.Add(new AesKey("x4ouqoqyhcnqojrgubso4hsdga",
                                    "ce92c6d1af345c645211ad49692b22338d128d974e3b6718c868e02776c873a9".DecodeHex()));

            Client.GetVaultAccounts("ru74fjxlkipzzctorwj4icrj2a", TestData.SesionKey, keychain, http);

            JsonHttpClientTest.VerifyGetUrl(http.Http, "1password.com/api/v1/vault");
        }

        [Test]
        public void SignOut_works()
        {
            var http = MakeJsonHttp(JsonHttpClientTest.SetupPut("{'success': 1}"));
            Client.SignOut(http);
        }

        [Test]
        public void SignOut_makes_PUT_request_to_specific_url()
        {
            var http = MakeJsonHttp(JsonHttpClientTest.SetupPut("{'success': 1}"));
            Client.SignOut(http);

            JsonHttpClientTest.VerifyPutUrl(http.Http, "1password.com/api/v1/session/signout");
        }

        [Test]
        public void SignOut_throws_on_bad_response()
        {
            var http = MakeJsonHttp(JsonHttpClientTest.SetupPut("{'success': 0}"));
            Assert.That(() => Client.SignOut(http),
                        ExceptionsTest.ThrowsRespondedWithErrorWithMessage("Failed to sign out"));
        }

        [Test]
        public void DecryptKeys_stores_keys_in_keychain()
        {
            var accountInfo = JObject.Parse(JsonHttpClientTest.ReadFixture("account-info"));
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

        [Test]
        public void GetApiUrl_returns_correct_url()
        {
            Assert.That(Client.GetApiUrl("my.1password.com"),
                        Is.EqualTo("https://my.1password.com/api"));
            Assert.That(Client.GetApiUrl("my.1password.eu"),
                        Is.EqualTo("https://my.1password.eu/api"));
        }

        [Test]
        public void MakeJsonClient_sets_base_url()
        {
            var http = Client.MakeJsonClient(new HttpClient(), "https://base.url");
            Assert.That(http.BaseUrl, Is.EqualTo("https://base.url"));
        }

        [Test]
        public void MakeJsonClient_copies_base_url()
        {
            var http = Client.MakeJsonClient(new JsonHttpClient(new HttpClient(), "https://base.url"));
            Assert.That(http.BaseUrl, Is.EqualTo("https://base.url"));
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
            uuid: "rz64r4uhyvgew672nm4ncaqonq",
            domain: "my.1password.com");

        //
        // Helpers
        //

        private static JsonHttpClient MakeJsonHttp(Mock<IHttpClient> http)
        {
            return new JsonHttpClient(http.Object, Client.GetApiUrl(Client.DefaultDomain));
        }
    }
}
