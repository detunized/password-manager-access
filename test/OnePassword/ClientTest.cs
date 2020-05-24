// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Linq;
using System.Net.Http;
using Newtonsoft.Json;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.OnePassword;
using Xunit;
using R = PasswordManagerAccess.OnePassword.Response;

namespace PasswordManagerAccess.Test.OnePassword
{
    public class ClientTest: TestBase
    {
        [Fact]
        public void StartNewSession_returns_session_on_ok()
        {
            var rest = new RestFlow().Get(GetFixture("start-new-session-response"));
            var session = Client.StartNewSession(TestData.ClientInfo, rest);

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
            var rest = new RestFlow()
                .Get(GetFixture("start-new-session-response"))
                .ExpectUrl("1password.com/api/v2/auth")
                .ToRestClient(ApiUrl);

            Client.StartNewSession(TestData.ClientInfo, rest);
        }

        [Fact]
        public void StartNewSession_throws_on_unknown_status()
        {
            var rest = new RestFlow().Get("{'status': 'unknown', 'sessionID': 'blah'}");

            Exceptions.AssertThrowsInternalError(() => Client.StartNewSession(TestData.ClientInfo, rest),
                                                 "Failed to start a new session, unsupported response status");
        }

        [Fact]
        public void StartNewSession_throws_on_network_error()
        {
            var error = new HttpRequestException("Network error");
            var rest = new RestFlow().Get(error);

            var e = Exceptions.AssertThrowsNetworkError(() => Client.StartNewSession(TestData.ClientInfo, rest),
                                                        "Network error");
            Assert.Same(error, e.InnerException);
        }

        [Fact]
        public void StartNewSession_throws_on_invalid_json()
        {
            var rest = new RestFlow().Get("} invalid json {");

            Exceptions.AssertThrowsInternalError(() => Client.StartNewSession(TestData.ClientInfo, rest),
                                                 "Invalid or unexpected response");
        }

        [Fact]
        public void RegisterDevice_works()
        {
            var rest = new RestFlow().Post("{'success': 1}");

            Client.RegisterDevice(TestData.ClientInfo, rest);
        }

        [Fact]
        public void RegisterDevice_makes_POST_request_to_specific_url()
        {
            var rest = new RestFlow()
                .Post("{'success': 1}")
                .ExpectUrl("1password.com/api/v1/device")
                .ToRestClient(ApiUrl);

            Client.RegisterDevice(TestData.ClientInfo, rest);
        }

        [Fact]
        public void RegisterDevice_throws_on_error()
        {
            var rest = new RestFlow().Post("{'success': 0}");

            Exceptions.AssertThrowsInternalError(() => Client.RegisterDevice(TestData.ClientInfo, rest),
                                                 "Failed to register the device");
        }

        [Fact]
        public void ReauthorizeDevice_works()
        {
            var rest = new RestFlow().Put("{'success': 1}");

            Client.ReauthorizeDevice(TestData.ClientInfo, rest);
        }

        [Fact]
        public void ReauthorizeDevice_makes_PUT_request_to_specific_url()
        {
            var rest = new RestFlow()
                .Put("{'success': 1}")
                .ExpectUrl("1password.com/api/v1/device")
                .ToRestClient(ApiUrl);

            Client.ReauthorizeDevice(TestData.ClientInfo, rest);
        }

        [Fact]
        public void ReauthorizeDevice_throws_on_error()
        {
            var rest = new RestFlow().Put("{'success': 0}");

            Exceptions.AssertThrowsInternalError(() => Client.ReauthorizeDevice(TestData.ClientInfo, rest),
                                                 "Failed to reauthorize the device");
        }

        [Fact]
        public void VerifySessionKey_returns_success()
        {
            var rest = new RestFlow().Post(EncryptFixture("verify-key-response"));
            var result = Client.VerifySessionKey(TestData.Session, TestData.SessionKey, rest);

            Assert.Equal(Client.VerifyStatus.Success, result.Status);
        }

        [Fact]
        public void VerifySessionKey_makes_POST_request_to_specific_url()
        {
            var rest = new RestFlow()
                .Post(EncryptFixture("verify-key-response"))
                .ExpectUrl("1password.com/api/v2/auth/verify")
                .ToRestClient(ApiUrl);

            Client.VerifySessionKey(TestData.Session, TestData.SessionKey, rest);
        }

        [Fact]
        public void VerifySessionKey_returns_factors()
        {
            var rest = new RestFlow().Post(EncryptFixture("verify-key-response-mfa"));
            var result = Client.VerifySessionKey(TestData.Session, TestData.SessionKey, rest);

            Assert.Equal(3, result.Factors.Length);
        }

        [Fact]
        public void VerifySessionKey_throws_BadCredentials_on_auth_error()
        {
            var rest = new RestFlow().Post(EncryptFixture("no-auth-response"));

            Exceptions.AssertThrowsBadCredentials(
                () => Client.VerifySessionKey(TestData.Session, TestData.SessionKey, rest),
                "Username, password or account key");
        }

        [Fact]
        public void GetSecondFactors_returns_factors()
        {
            var expected = new[]
            {
                Client.SecondFactorKind.GoogleAuthenticator,
                Client.SecondFactorKind.RememberMeToken,
                Client.SecondFactorKind.Duo,
            };
            var mfa = JsonConvert.DeserializeObject<R.MfaInfo>("{" +
                                                               "'duo': {'enabled': true}, " +
                                                               "'totp': {'enabled': true}, " +
                                                               "'dsecret': {'enabled': true}" +
                                                               "}");
            var factors = Client.GetSecondFactors(mfa)
                .Select(x => x.Kind)
                .ToArray();

            Assert.Equal(expected, factors);
        }

        [Fact]
        public void GetSecondFactors_ignores_missing_factors()
        {
            var expected = new[] { Client.SecondFactorKind.GoogleAuthenticator };
            var mfa = JsonConvert.DeserializeObject<R.MfaInfo>("{'totp': {'enabled': true}}");
            var factors = Client.GetSecondFactors(mfa)
                .Select(x => x.Kind)
                .ToArray();

            Assert.Equal(expected, factors);
        }

        [Fact]
        public void GetSecondFactors_ignores_disabled_factors()
        {
            var expected = new[] { Client.SecondFactorKind.GoogleAuthenticator };
            var mfa = JsonConvert.DeserializeObject<R.MfaInfo>("{" +
                                                               "'duo': {'enabled': false}, " +
                                                               "'totp': {'enabled': true}, " +
                                                               "'dsecret': {'enabled': false}" +
                                                               "}");
            var factors = Client.GetSecondFactors(mfa)
                .Select(x => x.Kind)
                .ToArray();

            Assert.Equal(expected, factors);
        }

        [Fact]
        public void ChooseInteractiveSecondFactor_returns_high_priority_factor()
        {
            var factors = new[]
            {
                new Client.SecondFactor(Client.SecondFactorKind.GoogleAuthenticator),
                new Client.SecondFactor(Client.SecondFactorKind.Duo),
            };
            var chosen = Client.ChooseInteractiveSecondFactor(factors);

            Assert.Equal(Client.SecondFactorKind.Duo, chosen.Kind);
        }

        [Fact]
        public void ChooseInteractiveSecondFactor_throws_on_empty_factors()
        {
            Exceptions.AssertThrowsInternalError(
                () => Client.ChooseInteractiveSecondFactor(new Client.SecondFactor[0]),
                "The list of 2FA methods is empty");
        }

        [Fact]
        public void ChooseInteractiveSecondFactor_throws_on_missing_factors()
        {
            var factors = new[] {new Client.SecondFactor(Client.SecondFactorKind.RememberMeToken)};

            Exceptions.AssertThrowsInternalError(() => Client.ChooseInteractiveSecondFactor(factors),
                                                 "doesn't contain any supported methods");
        }

        [Fact]
        public void SubmitSecondFactorCode_returns_remember_me_token()
        {
            var rest = new RestFlow().Post(EncryptFixture("mfa-response"));
            var token = Client.SubmitSecondFactorCode(Client.SecondFactorKind.GoogleAuthenticator,
                                                      "123456",
                                                      TestData.Session,
                                                      TestData.SessionKey,
                                                      rest);

            Assert.Equal("gUhBItRHUI7vAc04TJNUkA", token);
        }

        [Fact]
        public void SubmitSecondFactorCode_makes_POST_request_to_specific_url()
        {
            var rest = new RestFlow()
                .Post(EncryptFixture("mfa-response"))
                .ExpectUrl("1password.com/api/v1/auth/mfa")
                .ToRestClient(ApiUrl);

            Client.SubmitSecondFactorCode(Client.SecondFactorKind.GoogleAuthenticator,
                                          "123456",
                                          TestData.Session,
                                          TestData.SessionKey,
                                          rest);
        }

        [Fact]
        public void SubmitSecondFactorCode_throws_BadMultiFactor_on_auth_error()
        {
            var rest = new RestFlow().Post(EncryptFixture("no-auth-response"));

            Exceptions.AssertThrowsBadMultiFactor(
                () => Client.SubmitSecondFactorCode(Client.SecondFactorKind.GoogleAuthenticator,
                                                    "123456",
                                                    TestData.Session,
                                                    TestData.SessionKey,
                                                    rest),
                "Incorrect second factor code");
        }

        [Fact]
        public void GetAccountInfo_works()
        {
            var rest = new RestFlow().Get(EncryptFixture("get-account-info-response"));

            Client.GetAccountInfo(TestData.SessionKey, rest);
        }

        [Fact]
        public void GetAccountInfo_makes_GET_request_to_specific_url()
        {
            var rest = new RestFlow()
                .Get(EncryptFixture("get-account-info-response"))
                .ExpectUrl("1password.com/api/v1/account")
                .ToRestClient(ApiUrl);

            Client.GetAccountInfo(TestData.SessionKey, rest);
        }

        [Fact]
        public void GetKeysets_works()
        {
            var rest = new RestFlow().Get(EncryptFixture("get-keysets-response"));

            Client.GetKeysets(TestData.SessionKey, rest);
        }

        [Fact]
        public void GetKeysets_makes_GET_request_to_specific_url()
        {
            var rest = new RestFlow()
                .Get(EncryptFixture("get-keysets-response"))
                .ExpectUrl("1password.com/api/v1/account/keysets")
                .ToRestClient(ApiUrl);

            Client.GetKeysets(TestData.SessionKey, rest);
        }

        [Fact]
        public void BuildListOfAccessibleVaults_returns_vaults()
        {
            var accountInfo = ParseFixture<R.AccountInfo>("get-account-info-response");
            var vaults = Client.BuildListOfAccessibleVaults(accountInfo);

            Assert.Equal(new[] {"ru74fjxlkipzzctorwj4icrj2a", "4tz67op2kfiapodi5ygprtwn64"}, vaults);
        }

        [Fact]
        public void GetVaultAccounts_work()
        {
            var rest = new RestFlow().Get(EncryptFixture("get-vault-accounts-ru74-response"));
            var keychain = new Keychain();
            keychain.Add(new AesKey("x4ouqoqyhcnqojrgubso4hsdga",
                                    "ce92c6d1af345c645211ad49692b22338d128d974e3b6718c868e02776c873a9".DecodeHex()));

            Client.GetVaultAccounts("ru74fjxlkipzzctorwj4icrj2a", TestData.SessionKey, keychain, rest, null);
        }

        [Fact]
        public void GetVaultAccounts_with_no_items_work()
        {
            var rest = new RestFlow().Get(EncryptFixture("get-vault-with-no-items-response"));
            var keychain = new Keychain();
            keychain.Add(new AesKey("x4ouqoqyhcnqojrgubso4hsdga",
                                    "ce92c6d1af345c645211ad49692b22338d128d974e3b6718c868e02776c873a9".DecodeHex()));

            Client.GetVaultAccounts("ru74fjxlkipzzctorwj4icrj2a", TestData.SessionKey, keychain, rest, null);
        }

        [Fact]
        public void GetVaultAccounts_returns_server_secrets()
        {
            var rest = new RestFlow().Get(EncryptFixture("get-vault-with-server-secrets-response"));
            var keychain = new Keychain();
            keychain.Add(new AesKey("e2e2ungb5d4tl7ls4ohxwhtd2e",
                                    "518f5d0f72d118252c4a5ac0b87af54210bb0f4aee0210fe8adbe3343c8a11ea".DecodeHex()));

            var accounts = Client.GetVaultAccounts("6xkojw55yh4uo4vtdewghr5boi",
                                                   TestData.SessionKey,
                                                   keychain,
                                                   rest,
                                                   null);

            Assert.Contains(accounts, x => x.Name == "server-test");
        }

        [Fact]
        public void GetVaultAccounts_makes_GET_request_to_specific_url()
        {
            var rest = new RestFlow()
                .Get(EncryptFixture("get-vault-accounts-ru74-response"))
                .ExpectUrl("1password.com/api/v1/vault")
                .ToRestClient(ApiUrl);
            var keychain = new Keychain();
            keychain.Add(new AesKey("x4ouqoqyhcnqojrgubso4hsdga",
                                    "ce92c6d1af345c645211ad49692b22338d128d974e3b6718c868e02776c873a9".DecodeHex()));

            Client.GetVaultAccounts("ru74fjxlkipzzctorwj4icrj2a", TestData.SessionKey, keychain, rest, null);
        }

        [Fact]
        public void GetVaultAccounts_with_multiple_batches_returns_all_accounts()
        {
            var rest = new RestFlow()
                .Get(EncryptFixture("get-vault-accounts-ru74-batch-1-response"))
                .Get(EncryptFixture("get-vault-accounts-ru74-batch-2-response"))
                .Get(EncryptFixture("get-vault-accounts-ru74-batch-3-response"));
            var keychain = new Keychain();
            keychain.Add(new AesKey("x4ouqoqyhcnqojrgubso4hsdga",
                                    "ce92c6d1af345c645211ad49692b22338d128d974e3b6718c868e02776c873a9".DecodeHex()));

            var accounts = Client.GetVaultAccounts("ru74fjxlkipzzctorwj4icrj2a",
                                                   TestData.SessionKey,
                                                   keychain,
                                                   rest,
                                                   null);

            Assert.Equal(3, accounts.Length);
        }

        [Fact]
        public void SignOut_works()
        {
            var rest = new RestFlow().Put("{'success': 1}");

            Client.SignOut(rest);
        }

        [Fact]
        public void SignOut_makes_PUT_request_to_specific_url()
        {
            var rest = new RestFlow()
                .Put("{'success': 1}")
                .ExpectUrl("1password.com/api/v1/session/signout")
                .ToRestClient(ApiUrl);

            Client.SignOut(rest);
        }

        [Fact]
        public void SignOut_throws_on_bad_response()
        {
            var rest = new RestFlow().Put("{'success': 0}");

            Exceptions.AssertThrowsInternalError(() => Client.SignOut(rest), "Failed to sign out");
        }

        [Fact]
        public void DecryptKeys_returns_all_keys_in_keychain()
        {
            var accountInfo = ParseFixture<R.AccountInfo>("get-account-info-response");
            var keysets = ParseFixture<R.KeysetsInfo>("get-keysets-response");
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
        public void MakeRestClient_sets_base_url()
        {
            var rest = Client.MakeRestClient(null, "https://base.url");
            Assert.Equal("https://base.url", rest.BaseUrl);
        }

        [Fact]
        public void MakeRestClient_copies_base_url()
        {
            var http = Client.MakeRestClient(new RestClient(null, "https://base.url"));
            Assert.Equal("https://base.url", http.BaseUrl);
        }

        //
        // Helpers
        //

        private string EncryptFixture(string name)
        {
            var encrypted = TestData.SessionKey.Encrypt(GetFixture(name).ToBytes());
            return JsonConvert.SerializeObject(encrypted.ToDictionary());
        }

        //
        // Data
        //

        private const string ApiUrl = "https://my.1password.com/api";

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
    }
}
