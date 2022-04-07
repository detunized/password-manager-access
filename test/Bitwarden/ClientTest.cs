// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Net;
using Moq;
using Newtonsoft.Json;
using Xunit;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Bitwarden;
using PasswordManagerAccess.Bitwarden.Ui;
using Response = PasswordManagerAccess.Bitwarden.Response;

namespace PasswordManagerAccess.Test.Bitwarden
{
    public class ClientTest: TestBase
    {
        [Fact]
        public void RequestKdfIterationCount_returns_iteration_count()
        {
            var rest = new RestFlow()
                .Post("{'Kdf': 0, 'KdfIterations': 1337}")
                .ToRestClient();

            var count = Client.RequestKdfIterationCount(Username, rest);

            Assert.Equal(1337, count);
        }

        [Fact]
        public void RequestKdfIterationCount_makes_POST_request_to_specific_endpoint()
        {
            var rest = new RestFlow()
                .Post("{'Kdf': 0, 'KdfIterations': 1337}")
                    .ExpectUrl("/api/accounts/prelogin")
                .ToRestClient();

            Client.RequestKdfIterationCount(Username, rest);
        }

        [Fact]
        public void RequestKdfIterationCount_throws_on_unsupported_kdf_method()
        {
            var rest = new RestFlow()
                .Post("{'Kdf': 13, 'KdfIterations': 1337}")
                .ToRestClient();

            Exceptions.AssertThrowsUnsupportedFeature(() => Client.RequestKdfIterationCount(Username, rest), "KDF");
        }

        [Fact]
        public void Login_returns_auth_token_on_non_2fa_login()
        {
            var rest = new RestFlow()
                .Post("{'token_type': 'Bearer', 'access_token': 'wa-wa-wee-wa'}")
                .ToRestClient();

            var token = Client.Login(Username,
                                     PasswordHash,
                                     DeviceId,
                                     null,
                                     SetupSecureStorage(null),
                                     rest);

            Assert.Equal("Bearer wa-wa-wee-wa", token);
        }

        [Fact]
        public void Login_sends_remember_me_token_when_available()
        {
            var rest = new RestFlow()
                .Post("{'token_type': 'Bearer', 'access_token': 'wa-wa-wee-wa'}")
                    .ExpectContent($"twoFactorToken={RememberMeToken}", "twoFactorProvider=5")
                .ToRestClient();

            Client.Login(Username, PasswordHash, DeviceId, null, SetupSecureStorage(RememberMeToken), rest);
        }

        [Fact]
        public void Login_does_not_send_remember_me_token_when_not_available()
        {
            var rest = new RestFlow()
                .Post("{'token_type': 'Bearer', 'access_token': 'wa-wa-wee-wa'}")
                    .ExpectContent(c => Assert.DoesNotContain("twoFactorToken", c))
                    .ExpectContent(c => Assert.DoesNotContain("twoFactorProvider", c))
                .ToRestClient();

            Client.Login(Username, PasswordHash, DeviceId, null, SetupSecureStorage(null), rest);
        }

        [Fact]
        public void Login_asks_ui_to_choose_second_factor_method()
        {
            var rest = new RestFlow()
                .Post(GetFixture("login-mfa"), System.Net.HttpStatusCode.BadRequest)
                .Post("{'token_type': 'Bearer', 'access_token': 'wa-wa-wee-wa'}")
                .ToRestClient();

            var ui = new Mock<IUi>();
            ui.Setup(x => x.ChooseMfaMethod(It.IsAny<MfaMethod[]>())).Returns(MfaMethod.GoogleAuth);
            ui.Setup(x => x.ProvideGoogleAuthPasscode()).Returns(new Passcode("123456", false));

            Client.Login(Username, PasswordHash, DeviceId, ui.Object, SetupSecureStorage(null), rest);

            ui.Verify(x => x.ChooseMfaMethod(It.IsAny<MfaMethod[]>()), Times.Once);
        }

        [Fact]
        public void Login_throws_when_no_supported_second_factor_methods_are_available()
        {
            var rest = new RestFlow()
                .Post(GetFixture("login-mfa-unsupported-only"), System.Net.HttpStatusCode.BadRequest)
                .ToRestClient();

            Exceptions.AssertThrowsUnsupportedFeature(
                () => Client.Login(Username, PasswordHash, DeviceId, null, SetupSecureStorage(null), rest),
                "not supported");
        }

        [Fact]
        public void LoginCliApi_makes_POST_request_to_specific_endpoint_and_returns_result()
        {
            var rest = new RestFlow()
                .Post("{'token_type': 'Bearer', 'access_token': 'wa-wa-wee-wa', 'Kdf': 13, 'KdfIterations': 1337}")
                .ExpectUrl("/identity/connect/token");

            var result = Client.LoginCliApi(ClientId, ClientSecret, DeviceId, rest);

            Assert.Equal("Bearer", result.TokenType);
            Assert.Equal("wa-wa-wee-wa", result.AccessToken);
            Assert.Equal(13, result.KdfMethod);
            Assert.Equal(1337, result.KdfIterations);
        }

        [Fact]
        public void LoginCliApi_throws_on_incorrect_client_credentials()
        {
            var rest = new RestFlow()
                .Post("{'error':'invalid_client'}", status: HttpStatusCode.BadRequest)
                .ExpectUrl("/identity/connect/token");

            Exceptions.AssertThrowsBadCredentials(
                () => Client.LoginCliApi(ClientId, ClientSecret, DeviceId, rest),
                "Client ID or secret is incorrect");
        }

        [Fact]
        public void RequestAuthToken_returns_auth_token_response()
        {
            var rest = new RestFlow()
                .Post("{'token_type': 'Bearer', 'access_token': 'wa-wa-wee-wa'}")
                .ToRestClient();

            var response = Client.RequestAuthToken(Username, PasswordHash, DeviceId, rest);

            Assert.Equal("Bearer wa-wa-wee-wa", response.AuthToken);
            Assert.Null(response.RememberMeToken);
            Assert.Null(response.SecondFactor.Methods);
        }

        [Fact]
        public void RequestAuthToken_returns_second_factor_response()
        {
            var rest = new RestFlow()
                .Post(GetFixture("login-mfa"), System.Net.HttpStatusCode.BadRequest)
                .ToRestClient();

            var response = Client.RequestAuthToken(Username, PasswordHash, DeviceId, rest);

            Assert.Null(response.AuthToken);
            Assert.Null(response.RememberMeToken);

            var methods = response.SecondFactor.Methods.Keys;
            Assert.Equal(5, methods.Count);
            Assert.Contains(Response.SecondFactorMethod.GoogleAuth, methods);
            Assert.Contains(Response.SecondFactorMethod.Email, methods);
            Assert.Contains(Response.SecondFactorMethod.Duo, methods);
            Assert.Contains(Response.SecondFactorMethod.YubiKey, methods);
        }

        [Fact]
        public void RequestAuthToken_returns_remember_me_token_when_present()
        {
            var rest = new RestFlow()
                .Post("{'token_type': 'Bearer', 'access_token': 'wa-wa-wee-wa', 'TwoFactorToken': 'remember-me-token'}")
                .ToRestClient();

            var response = Client.RequestAuthToken(Username, PasswordHash, DeviceId, rest);

            Assert.Equal("Bearer wa-wa-wee-wa", response.AuthToken);
            Assert.Equal("remember-me-token", response.RememberMeToken);
            Assert.Null(response.SecondFactor.Methods);
        }

        [Fact]
        public void RequestAuthToken_makes_POST_request_to_specific_endpoint()
        {
            var rest = new RestFlow()
                .Post("{'token_type': 'Bearer', 'access_token': 'wa-wa-wee-wa'}")
                    .ExpectUrl("/identity/connect/token")
                .ToRestClient();

            Client.RequestAuthToken(Username, PasswordHash, DeviceId, rest);
        }

        [Fact]
        public void RequestAuthToken_sends_device_id()
        {
            var rest = new RestFlow()
                .Post("{'token_type': 'Bearer', 'access_token': 'wa-wa-wee-wa'}")
                    .ExpectContent("deviceIdentifier=device-id")
                .ToRestClient();

            Client.RequestAuthToken(Username, PasswordHash, DeviceId, rest);
        }

        [Fact]
        public void RequestAuthToken_sends_auth_email_header()
        {
            var rest = new RestFlow()
                .Post("{'token_type': 'Bearer', 'access_token': 'wa-wa-wee-wa'}")
                    .ExpectHeader("Auth-Email", "dXNlcm5hbWU")
                .ToRestClient();

            Client.RequestAuthToken(Username, PasswordHash, DeviceId, rest);
        }

        [Fact]
        public void RequestAuthToken_with_second_factor_options_adds_extra_parameters()
        {
            var rest = new RestFlow()
                .Post("{'token_type': 'Bearer', 'access_token': 'wa-wa-wee-wa'}")
                    .ExpectContent("twoFactorToken=code", "twoFactorProvider=2", "twoFactorRemember=1")
                .ToRestClient();

            Client.RequestAuthToken(Username,
                                    PasswordHash,
                                    DeviceId,
                                    new Client.SecondFactorOptions(Response.SecondFactorMethod.Duo, "code", true),
                                    rest);
        }

        [Fact]
        public void DownloadVault_returns_parsed_response()
        {
            var rest = new RestFlow()
                .Get(GetFixture("vault"))
                .ToRestClient();

            var response = Client.DownloadVault(rest, "token");

            Assert.StartsWith("2.XZ2v", response.Profile.Key);
            Assert.Equal(6, response.Ciphers.Length);
            Assert.Equal(2, response.Folders.Length);
        }

        [Fact]
        public void DownloadVault_makes_GET_request_to_specific_endpoint()
        {
            var rest = new RestFlow()
                .Get(GetFixture("vault"))
                    .ExpectUrl("/api/sync")
                .ToRestClient();

            Client.DownloadVault(rest, "token");
        }

        [Fact]
        public void DownloadVault_sets_auth_header()
        {
            var rest = new RestFlow()
                .Get(GetFixture("vault"))
                    .ExpectHeader("Authorization", "token")
                .ToRestClient();

            Client.DownloadVault(rest, "token");
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
        public void DecryptVault_assigns_collections_and_resolves_HidePassword()
        {
            var accounts = Client.DecryptVault(LoadVaultFixture("vault-with-collections"),
                                               "zTrKlq/dviZ7aFFyRLDdT8Zju2rRM80+NzDtCl4hvlc=".Decode64());

            Assert.Equal(3, accounts.Length);

            Assert.Equal("both", accounts[0].Name);
            Assert.Equal(new[] { "Default Collection", "Hidden pwd" }, accounts[0].Collections);
            Assert.False(accounts[0].HidePassword);

            Assert.Equal("hiddenonly", accounts[1].Name);
            Assert.Equal(new[] { "Hidden pwd" }, accounts[1].Collections);
            Assert.True(accounts[1].HidePassword);

            Assert.Equal("defonly", accounts[2].Name);
            Assert.Equal(new[] { "Default Collection" }, accounts[2].Collections);
            Assert.False(accounts[2].HidePassword);
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
            var account = Client.ParseAccountItem(vault.Ciphers[0], Key, null, folders, new Dictionary<string, Client.Collection>());

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

        private Response.Vault LoadVaultFixture(string name = "vault")
        {
            return JsonConvert.DeserializeObject<Response.Vault>(GetFixture(name));
        }

        //
        // Data
        //

        private const string Username = "username";
        private const string ClientId = "client-id";
        private const string ClientSecret = "client-secret";
        private const string DeviceId = "device-id";
        private const string RememberMeToken = "remember-me-token";
        private static readonly byte[] PasswordHash = "password-hash".ToBytes();
        private static readonly byte[] Kek = "SLBgfXoityZsz4ZWvpEPULPZMYGH6vSqh3PXTe5DmyM=".Decode64();
        private static readonly byte[] Key = "7Zo+OWHAKzu+Ovxisz38Na4en13SnoKHPxFngLUgLiHzSZCWbq42Mohdr6wInwcsWbbezoVaS2vwZlSlB6G7Mg==".Decode64();

        private const string EncryptedString = "2.8RPqQRT3z5dTQtNAE/2XWw==|cl1uG8jueR0kxPPklGjVJAGCJqaw+YwmDPyNJtIwsXg=|klc2vOsbPPZD5K1MDMf/nqSNLBrOMPVUNycgCgl6l44=";
        private const string Plaintext = "Hey, check this out!";
    }
}
