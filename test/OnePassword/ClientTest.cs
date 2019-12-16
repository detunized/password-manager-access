// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using Moq;
using Newtonsoft.Json.Linq;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.OnePassword;
using Xunit;
using HttpClient = PasswordManagerAccess.OnePassword.HttpClient;
using IHttpClient = PasswordManagerAccess.OnePassword.IHttpClient;
using JsonHttpClient = PasswordManagerAccess.OnePassword.JsonHttpClient;

// TODO: DRY up tests. There's quite a bit of copy-paste here.
// TODO: Creating encrypted test fixtures is a giant PITA and not very obvious what's going on.
//       Look into this. Maybe encrypt on the fly and store plain JSON response in the fixture.

namespace PasswordManagerAccess.Test.OnePassword
{
    public class ClientTest: TestBase
    {
        [Fact]
        public void StartNewSession_returns_session_on_ok()
        {
            var http = MakeJsonHttp(JsonHttpClientTest.SetupGet(GetFixture("start-new-session-response")));
            var session = Client.StartNewSession(TestData.ClientInfo, http);

            Assert.Equal(TestData.Session.Id, session.Id);
            Assert.Equal(TestData.Session.KeyFormat, session.KeyFormat);
            Assert.Equal(TestData.Session.KeyUuid, session.KeyUuid);
            Assert.Equal(TestData.Session.SrpMethod, session.SrpMethod);
            Assert.Equal(TestData.Session.KeyMethod, session.KeyMethod);
            Assert.Equal(TestData.Session.Iterations, session.Iterations);
            Assert.Equal(TestData.Session.Salt, session.Salt);
        }

        [Fact]
        public void StartNewSession_makes_GET_request_to_specific_url()
        {
            var http = MakeJsonHttp(JsonHttpClientTest.SetupGet(GetFixture("start-new-session-response")));
            Client.StartNewSession(TestData.ClientInfo, http);

            JsonHttpClientTest.VerifyGetUrl(http.Http, "1password.com/api/v2/auth");
        }

        [Fact]
        public void StartNewSession_throws_on_unknown_status()
        {
            var http = MakeJsonHttp(JsonHttpClientTest.SetupGet("{'status': 'unknown'}"));

            var e = Assert.Throws<ClientException>(() => Client.StartNewSession(TestData.ClientInfo, http));
            Assert.Equal(ClientException.FailureReason.InvalidResponse, e.Reason);
            Assert.Contains("Failed to start a new session", e.Message);
        }

        [Fact]
        public void StartNewSession_throws_on_network_error()
        {
            var jsonHttp = new JsonHttpClient(JsonHttpClientTest.SetupGetWithFailure().Object, "");

            var e = Assert.Throws<ClientException>(() => Client.StartNewSession(TestData.ClientInfo, jsonHttp));
            Assert.Equal(ClientException.FailureReason.NetworkError, e.Reason);
        }

        [Fact]
        public void StartNewSession_throws_on_invalid_json()
        {
            var jsonHttp = new JsonHttpClient(JsonHttpClientTest.SetupGet("} invalid json {").Object, "");

            var e = Assert.Throws<ClientException>(() => Client.StartNewSession(TestData.ClientInfo, jsonHttp));
            Assert.Equal(ClientException.FailureReason.InvalidResponse, e.Reason);
            Assert.Contains("Invalid JSON", e.Message);
        }

        [Fact]
        public void RegisterDevice_works()
        {
            var http = MakeJsonHttp(JsonHttpClientTest.SetupPost("{'success': 1}"));
            Client.RegisterDevice(TestData.ClientInfo, http);
        }

        [Fact]
        public void RegisterDevice_makes_POST_request_to_specific_url()
        {
            var http = MakeJsonHttp(JsonHttpClientTest.SetupPost("{'success': 1}"));
            Client.RegisterDevice(TestData.ClientInfo, http);

            JsonHttpClientTest.VerifyPostUrl(http.Http, "1password.com/api/v1/device");
        }

        [Fact]
        public void RegisterDevice_throws_on_error()
        {
            var http = MakeJsonHttp(JsonHttpClientTest.SetupPost("{'success': 0}"));

            var e = Assert.Throws<ClientException>(() => Client.RegisterDevice(TestData.ClientInfo, http));
            Assert.Equal(ClientException.FailureReason.RespondedWithError, e.Reason);
            Assert.Contains("Failed to register", e.Message);
        }

        [Fact]
        public void ReauthorizeDevice_works()
        {
            var http = MakeJsonHttp(JsonHttpClientTest.SetupPut("{'success': 1}"));
            Client.ReauthorizeDevice(TestData.ClientInfo, http);
        }

        [Fact]
        public void ReauthorizeDevice_makes_PUT_request_to_specific_url()
        {
            var http = MakeJsonHttp(JsonHttpClientTest.SetupPut("{'success': 1}"));
            Client.ReauthorizeDevice(TestData.ClientInfo, http);

            JsonHttpClientTest.VerifyPutUrl(http.Http, "1password.com/api/v1/device");
        }

        [Fact]
        public void ReauthorizeDevice_throws_on_error()
        {
            var http = MakeJsonHttp(JsonHttpClientTest.SetupPut("{'success': 0}"));

            var e = Assert.Throws<ClientException>(() => Client.ReauthorizeDevice(TestData.ClientInfo, http));
            Assert.Equal(ClientException.FailureReason.RespondedWithError, e.Reason);
            Assert.Contains("Failed to reauthorize", e.Message);
        }

        [Fact]
        public void VerifySessionKey_returns_success()
        {
            var http = MakeJsonHttp(JsonHttpClientTest.SetupPost(GetFixture("verify-key-response")));
            var result = Client.VerifySessionKey(TestData.ClientInfo, TestData.Session, TestData.SesionKey, http);

            Assert.Equal(Client.VerifyStatus.Success, result.Status);
        }

        [Fact]
        public void VerifySessionKey_makes_POST_request_to_specific_url()
        {
            var http = MakeJsonHttp(JsonHttpClientTest.SetupPost(GetFixture("verify-key-response")));
            Client.VerifySessionKey(TestData.ClientInfo, TestData.Session, TestData.SesionKey, http);

            JsonHttpClientTest.VerifyPostUrl(http.Http, "1password.com/api/v2/auth/verify");
        }

        [Fact]
        public void ParseSecondFactors_returns_factors()
        {
            var json = JToken.Parse("{'totp': {'enabled': true}, 'dsecret': {'enabled': true}}");
            var factors = Client.ParseSecondFactors(json);

            Assert.Equal(new[] { Client.SecondFactor.GoogleAuthenticator, Client.SecondFactor.RememberMeToken },
                         factors);
        }

        [Fact]
        public void ParseSecondFactor_ignores_missing_factors()
        {
            var json = JToken.Parse("{'totp': {'enabled': true}}");
            var factors = Client.ParseSecondFactors(json);

            Assert.Equal(new[] { Client.SecondFactor.GoogleAuthenticator }, factors);
        }

        [Fact]
        public void ParseSecondFactor_ignores_disabled_factors()
        {
            var json = JToken.Parse("{'totp': {'enabled': true}, 'dsecret': {'enabled': false}}");
            var factors = Client.ParseSecondFactors(json);

            Assert.Equal(new[] { Client.SecondFactor.GoogleAuthenticator }, factors);
        }

        [Fact]
        public void GetAccountInfo_works()
        {
            var http = MakeJsonHttp(JsonHttpClientTest.SetupGet(GetFixture("get-account-info-response")));
            Client.GetAccountInfo(TestData.SesionKey, http);
        }

        [Fact]
        public void GetAccountInfo_makes_GET_request_to_specific_url()
        {
            var http = MakeJsonHttp(JsonHttpClientTest.SetupGet(GetFixture("get-account-info-response")));
            Client.GetAccountInfo(TestData.SesionKey, http);

            JsonHttpClientTest.VerifyGetUrl(http.Http, "1password.com/api/v1/account");
        }

        [Fact]
        public void GetKeysets_works()
        {
            var http = MakeJsonHttp(JsonHttpClientTest.SetupGet(GetFixture("empty-object-response")));
            Client.GetKeysets(TestData.SesionKey, http);
        }

        [Fact]
        public void GetKeysets_makes_GET_request_to_specific_url()
        {
            var http = MakeJsonHttp(JsonHttpClientTest.SetupGet(GetFixture("empty-object-response")));
            Client.GetKeysets(TestData.SesionKey, http);

            JsonHttpClientTest.VerifyGetUrl(http.Http, "1password.com/api/v1/account/keysets");
        }

        [Fact]
        public void BuildListOfAccessibleVaults_returns_vaults()
        {
            var accountInfo = JObject.Parse(GetFixture("account-info"));
            var vaults = Client.BuildListOfAccessibleVaults(accountInfo);

            Assert.Equal(new[] {"ru74fjxlkipzzctorwj4icrj2a", "4tz67op2kfiapodi5ygprtwn64"}, vaults);
        }

        [Fact]
        public void GetVaultAccounts_work()
        {
            var http = MakeJsonHttp(JsonHttpClientTest.SetupGet(GetFixture("get-vault-accounts-ru74-response")));
            var keychain = new Keychain();
            keychain.Add(new AesKey("x4ouqoqyhcnqojrgubso4hsdga",
                                    "ce92c6d1af345c645211ad49692b22338d128d974e3b6718c868e02776c873a9".DecodeHex()));

            Client.GetVaultAccounts("ru74fjxlkipzzctorwj4icrj2a", TestData.SesionKey, keychain, http, null);
        }

        [Fact]
        public void GetVaultAccounts_with_no_items_work()
        {
            var http = MakeJsonHttp(JsonHttpClientTest.SetupGet(GetFixture("get-vault-with-no-items-response")));
            var keychain = new Keychain();
            keychain.Add(new AesKey("x4ouqoqyhcnqojrgubso4hsdga",
                                    "ce92c6d1af345c645211ad49692b22338d128d974e3b6718c868e02776c873a9".DecodeHex()));

            Client.GetVaultAccounts("ru74fjxlkipzzctorwj4icrj2a", TestData.SesionKey, keychain, http, null);
        }

        [Fact]
        public void GetVaultAccounts_makes_GET_request_to_specific_url()
        {
            var http = MakeJsonHttp(JsonHttpClientTest.SetupGet(GetFixture("get-vault-accounts-ru74-response")));
            var keychain = new Keychain();
            keychain.Add(new AesKey("x4ouqoqyhcnqojrgubso4hsdga",
                                    "ce92c6d1af345c645211ad49692b22338d128d974e3b6718c868e02776c873a9".DecodeHex()));

            Client.GetVaultAccounts("ru74fjxlkipzzctorwj4icrj2a", TestData.SesionKey, keychain, http, null);

            JsonHttpClientTest.VerifyGetUrl(http.Http, "1password.com/api/v1/vault");
        }

        [Fact]
        public void SignOut_works()
        {
            var http = MakeJsonHttp(JsonHttpClientTest.SetupPut("{'success': 1}"));
            Client.SignOut(http);
        }

        [Fact]
        public void SignOut_makes_PUT_request_to_specific_url()
        {
            var http = MakeJsonHttp(JsonHttpClientTest.SetupPut("{'success': 1}"));
            Client.SignOut(http);

            JsonHttpClientTest.VerifyPutUrl(http.Http, "1password.com/api/v1/session/signout");
        }

        [Fact]
        public void SignOut_throws_on_bad_response()
        {
            var http = MakeJsonHttp(JsonHttpClientTest.SetupPut("{'success': 0}"));

            var e = Assert.Throws<ClientException>(() => Client.SignOut(http));
            Assert.Equal(ClientException.FailureReason.RespondedWithError, e.Reason);
            Assert.Contains("Failed to sign out", e.Message);
        }

        [Fact]
        public void DecryptKeys_returns_all_keys_in_keychain()
        {
            var accountInfo = JObject.Parse(GetFixture("account-info"));
            var keysets = JObject.Parse(GetFixture("keysets"));
            var keychain = Client.DecryptAllKeys(accountInfo, keysets, ClientInfo);

            var aesKeys = new[]
            {
                "mp",
                "x4ouqoqyhcnqojrgubso4hsdga",
                "byq5gi5adlasqyy2l2o7iddzvq",
            };

            foreach (var i in aesKeys)
                Assert.NotNull(keychain.GetAes(i));

            var keysetIds = new[]
            {
                "szerdhg2ww2ahjo4ilz57x7cce",
                "yf2ji37vkqdow7pnbo3y37b3lu",
                "srkx3r5c3qgyzsdswfc4awgh2m",
                "sm5hkw3mxwdcwcgljf4kyplwea",
            };

            foreach (var i in keysetIds)
            {
                Assert.NotNull(keychain.GetAes(i));
                Assert.NotNull(keychain.GetRsa(i));
            }
        }

        [Fact]
        public void DeriveMasterKey_returns_master_key()
        {
            var expected = "09f6cf6acc4f64f2ac6af5d912427253c4dd5e1a48dfc6bfea21df8f6d3a701e".DecodeHex();
            var key = Client.DeriveMasterKey("PBES2g-HS256",
                                             100000,
                                             "i2enf0xq-XPKCFFf5UZqNQ".Decode64Loose(),
                                             TestData.ClientInfo);

            Assert.Equal("mp", key.Id);
            Assert.Equal(expected, key.Key);
        }

        [Fact]
        public void GetApiUrl_returns_correct_url()
        {
            Assert.Equal("https://my.1password.com/api", Client.GetApiUrl("my.1password.com"));
            Assert.Equal("https://my.1password.eu/api", Client.GetApiUrl("my.1password.eu"));
        }

        [Fact]
        public void MakeJsonClient_sets_base_url()
        {
            var http = Client.MakeJsonClient(new HttpClient(), "https://base.url");
            Assert.Equal("https://base.url", http.BaseUrl);
        }

        [Fact]
        public void MakeJsonClient_copies_base_url()
        {
            var http = Client.MakeJsonClient(new JsonHttpClient(new HttpClient(), "https://base.url"));
            Assert.Equal("https://base.url", http.BaseUrl);
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
