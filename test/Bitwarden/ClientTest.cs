// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using Moq;
using Newtonsoft.Json;
using Xunit;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Bitwarden;
using PasswordManagerAccess.Test.Common;
using Response = PasswordManagerAccess.Bitwarden.Response;

#if TESTS_ARE_FIXED
namespace PasswordManagerAccess.Test.Bitwarden
{
    public class ClientTest: TestBase
    {
        [Fact]
        public void RequestKdfIterationCount_returns_iteration_count()
        {
            var count = Client.RequestKdfIterationCount(Username, SetupKdfRequest(1337));

            Assert.Equal(1337, count);
        }

        [Fact]
        public void RequestKdfIterationCount_makes_POST_request_to_specific_endpoint()
        {
            var jsonHttp = SetupKdfRequest(1337);
            Client.RequestKdfIterationCount(Username, jsonHttp);

            JsonHttpClientTest.VerifyPostUrl(jsonHttp, ".com/api/accounts/prelogin");
        }

        [Fact]
        public void RequestKdfIterationCount_throws_on_unsupported_kdf_method()
        {
            var jsonHttp = SetupKdfRequest(1337, 13);
            Exceptions.AssertThrowsUnsupportedFeature(() => Client.RequestKdfIterationCount(Username, jsonHttp), "KDF");
        }

        [Fact]
        public void Login_returns_auth_token_on_non_2fa_login()
        {
            var token = Client.Login(Username,
                                     PasswordHash,
                                     DeviceId,
                                     null,
                                     SetupSecureStorage(null),
                                     SetupAuthTokenRequest());

            Assert.Equal("Bearer wa-wa-wee-wa", token);
        }

        [Fact]
        public void Login_sends_remember_me_token_when_available()
        {
            var jsonHttp = SetupAuthTokenRequest();
            Client.Login(Username, PasswordHash, DeviceId, null, SetupSecureStorage(RememberMeToken), jsonHttp);

            Mock.Get(jsonHttp.Http).Verify(x => x.Post(
                It.IsAny<string>(),
                It.Is<string>(s => s.Contains($"twoFactorToken={RememberMeToken}") &&
                                   s.Contains("twoFactorProvider=5")),
                It.IsAny<Dictionary<string, string>>()));
        }

        [Fact]
        public void Login_does_not_send_remember_me_token_when_not_available()
        {
            var jsonHttp = SetupAuthTokenRequest();
            Client.Login(Username, PasswordHash, DeviceId, null, SetupSecureStorage(null), jsonHttp);

            Mock.Get(jsonHttp.Http).Verify(x => x.Post(
                It.IsAny<string>(),
                It.Is<string>(s => !s.Contains("twoFactorToken") && !s.Contains("twoFactorProvider")),
                It.IsAny<Dictionary<string, string>>()));
        }

        [Fact]
        public void RequestAuthToken_returns_auth_token_response()
        {
            var response = Client.RequestAuthToken(Username, PasswordHash, DeviceId, SetupAuthTokenRequest());

            Assert.Equal("Bearer wa-wa-wee-wa", response.AuthToken);
            Assert.Null(response.RememberMeToken);
            Assert.Null(response.SecondFactor.Methods);
        }

        [Fact]
        public void RequestAuthToken_returns_remember_me_token_when_present()
        {
            var response = Client.RequestAuthToken(Username,
                                                   PasswordHash,
                                                   DeviceId,
                                                   SetupAuthTokenRequestWithRememberMeToken());

            Assert.Equal("Bearer wa-wa-wee-wa", response.AuthToken);
            Assert.Equal(RememberMeToken, response.RememberMeToken);
            Assert.Null(response.SecondFactor.Methods);
        }

        [Fact]
        public void RequestAuthToken_makes_POST_request_to_specific_endpoint()
        {
            var jsonHttp = SetupAuthTokenRequest();
            Client.RequestAuthToken(Username, PasswordHash, DeviceId, jsonHttp);

            JsonHttpClientTest.VerifyPostUrl(jsonHttp, ".com/identity/connect/token");
        }

        [Fact]
        public void RequestAuthToken_sends_device_id()
        {
            var jsonHttp = SetupAuthTokenRequest();
            Client.RequestAuthToken(Username, PasswordHash, DeviceId, jsonHttp);

            Mock.Get(jsonHttp.Http).Verify(x => x.Post(
                It.IsAny<string>(),
                It.Is<string>(s => s.Contains("deviceIdentifier=device-id")),
                It.IsAny<Dictionary<string, string>>()));
        }

        [Fact]
        public void RequestAuthToken_with_second_factor_options_adds_extra_parameters()
        {
            var jsonHttp = SetupAuthTokenRequest();
            Client.RequestAuthToken(Username,
                                    PasswordHash,
                                    DeviceId,
                                    new Client.SecondFactorOptions(Response.SecondFactorMethod.Duo, "code", true),
                                    jsonHttp);

            Mock.Get(jsonHttp.Http).Verify(x => x.Post(
                It.IsAny<string>(),
                It.Is<string>(s => s.Contains("twoFactorToken=code") &&
                                   s.Contains("twoFactorProvider=2") &&
                                   s.Contains("twoFactorRemember=1")),
                It.IsAny<Dictionary<string, string>>()));
        }

        [Fact]
        public void DownloadVault_returns_parsed_response()
        {
            var jsonHttp = SetupDownloadVault();
            var response = Client.DownloadVault(jsonHttp);

            Assert.StartsWith("2.XZ2v", response.Profile.Key);
            Assert.Equal(6, response.Ciphers.Length);
            Assert.Equal(2, response.Folders.Length);
        }

        [Fact]
        public void DownloadVault_makes_GET_request_to_specific_endpoint()
        {
            var jsonHttp = SetupDownloadVault();
            Client.DownloadVault(jsonHttp);

            JsonHttpClientTest.VerifyGetUrl(jsonHttp, ".com/api/sync");
        }

        [Fact]
        public void DecryptVault_returns_accounts()
        {
            var accounts = Client.DecryptVault(LoadVaultFixture(), Kek);

            Assert.Equal(3, accounts.Length);
            Assert.Equal("Facebook", accounts[0].Name);
            Assert.Equal("Google", accounts[1].Name);
            Assert.Equal("only name", accounts[2].Name);
        }

        [Fact]
        public void DecryptVault_assigns_folders()
        {
            var accounts = Client.DecryptVault(LoadVaultFixture(), Kek);

            Assert.Equal("Facebook", accounts[0].Name);
            Assert.Equal("folder2", accounts[0].Folder);

            Assert.Equal("Google", accounts[1].Name);
            Assert.Equal("", accounts[1].Folder);

            Assert.Equal("only name", accounts[2].Name);
            Assert.Equal("folder1", accounts[2].Folder);
        }

        [Fact]
        public void ParseAccountItem_returns_account()
        {
            var vault = LoadVaultFixture();
            var folders = new Dictionary<string, string>
            {
                {"d0e9210c-610b-4427-a344-a99600d462d3", "folder1"},
                {"94542f0a-d858-46ce-87a5-a99600d47732", "folder2"},
            };
            var account = Client.ParseAccountItem(vault.Ciphers[0], Key, null, folders);

            Assert.Equal("a323db80-891a-4d91-9304-a981014cf3ca", account.Id);
            Assert.Equal("Facebook", account.Name);
            Assert.Equal("mark", account.Username);
            Assert.Equal("zuckerberg", account.Password);
            Assert.Equal("https://facebook.com", account.Url);
            Assert.Equal("Hey, check this out!", account.Note);
            Assert.Equal("folder2", account.Folder);
        }

        [Fact]
        public void DecryptToBytes_returns_decrypted_input()
        {
            var plaintext = Client.DecryptToBytes(EncryptedString, Key);
            Assert.Equal(Plaintext.ToBytes(), plaintext);
        }

        [Fact]
        public void DecryptToString_returns_decrypted_input()
        {
            var plaintext = Client.DecryptToString(EncryptedString, Key);
            Assert.Equal(Plaintext, plaintext);
        }

        [Fact]
        public void DecryptToStringOrBlank_returns_decrypted_input()
        {
            var plaintext = Client.DecryptToStringOrBlank(EncryptedString, Key);
            Assert.Equal(Plaintext, plaintext);
        }

        [Fact]
        public void DecryptToStringOrBlank_returns_blank_for_null_input()
        {
            var blank = Client.DecryptToStringOrBlank(null, Key);
            Assert.Equal("", blank);
        }

        //
        // Helpers
        //

        private ISecureStorage SetupSecureStorage(string token)
        {
            var mock = new Mock<ISecureStorage>();
            mock.Setup(x => x.LoadString(It.IsAny<string>())).Returns(token);
            return mock.Object;
        }

        private JsonHttpClient SetupKdfRequest(int iteratons, int method = (int)Response.KdfMethod.Pbkdf2Sha256)
        {
            return SetupPost($"{{'Kdf': {method}, 'KdfIterations': {iteratons}}}");
        }

        private JsonHttpClient SetupAuthTokenRequest()
        {
            return SetupPost("{'token_type': 'Bearer', 'access_token': 'wa-wa-wee-wa'}");
        }

        private JsonHttpClient SetupAuthTokenRequestWithRememberMeToken()
        {
            return SetupPost("{'token_type': 'Bearer', 'access_token': 'wa-wa-wee-wa', 'TwoFactorToken': 'remember-me-token'}");
        }

        private JsonHttpClient SetupDownloadVault()
        {
            return SetupGetWithFixture("vault");
        }

        private JsonHttpClient SetupGetWithFixture(string name)
        {
            return MakeJsonHttp(JsonHttpClientTest.SetupGet(GetFixture(name)));
        }

        private JsonHttpClient SetupPost(string response)
        {
            return MakeJsonHttp(JsonHttpClientTest.SetupPost(response));
        }

        private JsonHttpClient MakeJsonHttp(Mock<IHttpClient> http)
        {
            return new JsonHttpClient(http.Object, "https://vault.bitwarden.com");
        }

        private Response.Vault LoadVaultFixture()
        {
            return JsonConvert.DeserializeObject<Response.Vault>(GetFixture("vault"));
        }

        //
        // Data
        //

        private const string Username = "username";
        private const string DeviceId = "device-id";
        private const string RememberMeToken = "remember-me-token";
        private static readonly byte[] PasswordHash = "password-hash".ToBytes();
        private static readonly byte[] Kek = "SLBgfXoityZsz4ZWvpEPULPZMYGH6vSqh3PXTe5DmyM=".Decode64();
        private static readonly byte[] Key = "7Zo+OWHAKzu+Ovxisz38Na4en13SnoKHPxFngLUgLiHzSZCWbq42Mohdr6wInwcsWbbezoVaS2vwZlSlB6G7Mg==".Decode64();

        private const string EncryptedString = "2.8RPqQRT3z5dTQtNAE/2XWw==|cl1uG8jueR0kxPPklGjVJAGCJqaw+YwmDPyNJtIwsXg=|klc2vOsbPPZD5K1MDMf/nqSNLBrOMPVUNycgCgl6l44=";
        private const string Plaintext = "Hey, check this out!";
    }
}
#endif
