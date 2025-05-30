// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Net;
using Newtonsoft.Json;
using PasswordManagerAccess.Bitwarden;
using PasswordManagerAccess.Bitwarden.Ui;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Duo;
using Shouldly;
using Xunit;
using MfaMethod = PasswordManagerAccess.Bitwarden.Ui.MfaMethod;
using R = PasswordManagerAccess.Bitwarden.Response;

namespace PasswordManagerAccess.Test.Bitwarden
{
    public class ClientTest : TestBase
    {
        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void MakeRestClients_returns_default_urls(string baseUrl)
        {
            var rest = Client.MakeRestClients(baseUrl, new RestFlow());

            Assert.Equal(ApiUrl, rest.Api.BaseUrl);
            Assert.Equal(IdentityUrl, rest.Identity.BaseUrl);
        }

        [Theory]
        [InlineData("https://base.url")]
        [InlineData("https://base.url/")]
        public void MakeRestClients_combines_base_url_with_endpoints(string baseUrl)
        {
            var rest = Client.MakeRestClients(baseUrl, new RestFlow());

            Assert.Equal("https://base.url/api", rest.Api.BaseUrl);
            Assert.Equal("https://base.url/identity", rest.Identity.BaseUrl);
        }

        [Fact]
        public void RequestKdfInfo_returns_kdf_info_pbkdf2()
        {
            var rest = new RestFlow().Post("{'kdf': 0, 'kdfIterations': 1337, 'kdfMemory': null, 'kdfParallelism': null}").ToRestClient();

            var kdf = Client.RequestKdfInfo(Username, rest);

            Assert.Equal(R.KdfMethod.Pbkdf2Sha256, kdf.Kdf);
            Assert.Equal(1337, kdf.Iterations);
        }

        [Fact]
        public void RequestKdfInfo_returns_kdf_info_argon2di()
        {
            var rest = new RestFlow().Post("{'kdf': 1, 'kdfIterations': 3, 'kdfMemory': 64, 'kdfParallelism': 4}").ToRestClient();

            var kdf = Client.RequestKdfInfo(Username, rest);

            Assert.Equal(R.KdfMethod.Argon2id, kdf.Kdf);
            Assert.Equal(3, kdf.Iterations);
            Assert.Equal(64, kdf.Memory);
            Assert.Equal(4, kdf.Parallelism);
        }

        [Fact]
        public void RequestKdfInfo_makes_POST_request_to_specific_endpoint()
        {
            var rest = new RestFlow()
                .Post("{'Kdf': 0, 'KdfIterations': 1337, 'kdfMemory': null, 'kdfParallelism': null}")
                .ExpectUrl(ApiUrl + "/accounts/prelogin")
                .ToRestClient(ApiUrl);

            Client.RequestKdfInfo(Username, rest);
        }

        [Fact]
        public void RequestKdfInfo_throws_on_unsupported_kdf_method()
        {
            var rest = new RestFlow().Post("{'Kdf': 13, 'KdfIterations': 1337, 'kdfMemory': null, 'kdfParallelism': null}").ToRestClient();

            Exceptions.AssertThrowsUnsupportedFeature(() => Client.RequestKdfInfo(Username, rest), "KDF method");
        }

        [Fact]
        public void Login_returns_auth_token_on_non_2fa_login()
        {
            var apiRest = new RestFlow();
            var idRest = new RestFlow()
                .Post("{'token_type': 'Bearer', 'access_token': 'wa-wa-wee-wa'}")
                .ExpectUrl(IdentityUrl + "/connect/token")
                .ToRestClient(IdentityUrl);

            var token = Client.Login(Username, PasswordHash, DeviceId, null, SetupSecureStorage(null), apiRest, idRest);

            Assert.Equal("Bearer wa-wa-wee-wa", token);
        }

        [Fact]
        public void Login_sends_remember_me_token_when_available()
        {
            var apiRest = new RestFlow();
            var idRest = new RestFlow()
                .Post("{'token_type': 'Bearer', 'access_token': 'wa-wa-wee-wa'}")
                .ExpectUrl(IdentityUrl + "/connect/token")
                .ExpectContent($"twoFactorToken={RememberMeToken}", "twoFactorProvider=5")
                .ToRestClient(IdentityUrl);

            Client.Login(Username, PasswordHash, DeviceId, null, SetupSecureStorage(RememberMeToken), apiRest, idRest);
        }

        [Fact]
        public void Login_does_not_send_remember_me_token_when_not_available()
        {
            var apiRest = new RestFlow();
            var idRest = new RestFlow()
                .Post("{'token_type': 'Bearer', 'access_token': 'wa-wa-wee-wa'}")
                .ExpectUrl(IdentityUrl + "/connect/token")
                .ExpectContent(c => Assert.DoesNotContain("twoFactorToken", c))
                .ExpectContent(c => Assert.DoesNotContain("twoFactorProvider", c))
                .ToRestClient(IdentityUrl);

            Client.Login(Username, PasswordHash, DeviceId, null, SetupSecureStorage(null), apiRest, idRest);
        }

        [Fact]
        public void Login_asks_ui_to_choose_second_factor_method()
        {
            // Arrange
            var apiRest = new RestFlow();
            var idRest = new RestFlow()
                .Post(GetFixture("login-mfa"), HttpStatusCode.BadRequest)
                .ExpectUrl(IdentityUrl + "/connect/token")
                .Post("{'token_type': 'Bearer', 'access_token': 'wa-wa-wee-wa'}")
                .ExpectUrl(IdentityUrl + "/connect/token")
                .ToRestClient(IdentityUrl);
            var ui = new GoogleAuthProvidingUi();

            // Act
            Client.Login(Username, PasswordHash, DeviceId, ui, SetupSecureStorage(null), apiRest, idRest);

            // Assert
            ui.ChooseMfaMethodCalledTimes.ShouldBe(1);
            ui.ProvideGoogleAuthPasscodeCalledTimes.ShouldBe(1);
            ui.CloseCalledTimes.ShouldBe(1);
        }

        [Fact]
        public void Login_throws_when_no_supported_second_factor_methods_are_available()
        {
            var apiRest = new RestFlow();
            var idRest = new RestFlow()
                .Post(GetFixture("login-mfa-unsupported-only"), HttpStatusCode.BadRequest)
                .ExpectUrl(IdentityUrl + "/connect/token")
                .ToRestClient(IdentityUrl);

            Exceptions.AssertThrowsUnsupportedFeature(
                () => Client.Login(Username, PasswordHash, DeviceId, null, SetupSecureStorage(null), apiRest, idRest),
                "not supported"
            );
        }

        [Fact]
        public void LoginCliApi_makes_POST_request_to_specific_endpoint_and_returns_result_pbdkf2()
        {
            var rest = new RestFlow()
                .Post(
                    "{'token_type': 'Bearer', 'access_token': 'wa-wa-wee-wa', 'Kdf': 0, 'KdfIterations': 1337, 'KdfMemory': null, 'KdfParallelism': null}"
                )
                .ExpectUrl(IdentityUrl + "/connect/token")
                .ToRestClient(IdentityUrl);

            var (token, kdfInfo) = Client.LogInCliApi(ClientId, ClientSecret, DeviceId, rest);

            Assert.Equal("Bearer wa-wa-wee-wa", token);
            Assert.Equal(R.KdfMethod.Pbkdf2Sha256, kdfInfo.Kdf);
            Assert.Equal(1337, kdfInfo.Iterations);
        }

        [Fact]
        public void LoginCliApi_makes_POST_request_to_specific_endpoint_and_returns_result_argon2id()
        {
            var rest = new RestFlow()
                .Post("{'token_type': 'Bearer', 'access_token': 'wa-wa-wee-wa', 'Kdf': 1, 'KdfIterations': 3, 'KdfMemory': 64, 'KdfParallelism': 4}")
                .ExpectUrl(IdentityUrl + "/connect/token")
                .ToRestClient(IdentityUrl);

            var (token, kdfInfo) = Client.LogInCliApi(ClientId, ClientSecret, DeviceId, rest);

            Assert.Equal("Bearer wa-wa-wee-wa", token);
            Assert.Equal(R.KdfMethod.Argon2id, kdfInfo.Kdf);
            Assert.Equal(3, kdfInfo.Iterations);
            Assert.Equal(64, kdfInfo.Memory);
            Assert.Equal(4, kdfInfo.Parallelism);
        }

        [Fact]
        public void LoginCliApi_throws_on_unsupported_kdf()
        {
            var rest = new RestFlow()
                .Post(
                    "{'token_type': 'Bearer', 'access_token': 'wa-wa-wee-wa', 'Kdf': 13, 'KdfIterations': 1337, 'KdfMemory': null, 'KdfParallelism': null}"
                )
                .ToRestClient(IdentityUrl);

            Exceptions.AssertThrowsUnsupportedFeature(() => Client.LogInCliApi(ClientId, ClientSecret, DeviceId, rest), "KDF method");
        }

        [Fact]
        public void LoginCliApi_throws_on_incorrect_client_credentials()
        {
            var rest = new RestFlow()
                .Post("{'error':'invalid_client'}", status: HttpStatusCode.BadRequest)
                .ExpectUrl(IdentityUrl + "/connect/token")
                .ToRestClient(IdentityUrl);

            Exceptions.AssertThrowsBadCredentials(
                () => Client.LogInCliApi(ClientId, ClientSecret, DeviceId, rest),
                "Client ID or secret is incorrect"
            );
        }

        [Fact]
        public void RequestAuthToken_returns_auth_token_response()
        {
            var rest = new RestFlow()
                .Post("{'token_type': 'Bearer', 'access_token': 'wa-wa-wee-wa'}")
                .ExpectUrl(IdentityUrl + "/connect/token")
                .ToRestClient(IdentityUrl);

            var response = Client.RequestAuthToken(Username, PasswordHash, DeviceId, rest);

            Assert.Equal("Bearer wa-wa-wee-wa", response.AuthToken);
            Assert.Null(response.RememberMeToken);
            Assert.Null(response.SecondFactor.Methods);
        }

        [Fact]
        public void RequestAuthToken_returns_second_factor_response()
        {
            var rest = new RestFlow()
                .Post(GetFixture("login-mfa"), HttpStatusCode.BadRequest)
                .ExpectUrl(IdentityUrl + "/connect/token")
                .ToRestClient(IdentityUrl);

            var response = Client.RequestAuthToken(Username, PasswordHash, DeviceId, rest);

            Assert.Null(response.AuthToken);
            Assert.Null(response.RememberMeToken);

            var methods = response.SecondFactor.Methods.Keys;
            Assert.Equal(5, methods.Count);
            Assert.Contains(R.SecondFactorMethod.GoogleAuth, methods);
            Assert.Contains(R.SecondFactorMethod.Email, methods);
            Assert.Contains(R.SecondFactorMethod.Duo, methods);
            Assert.Contains(R.SecondFactorMethod.YubiKey, methods);
        }

        [Fact]
        public void RequestAuthToken_returns_remember_me_token_when_present()
        {
            var rest = new RestFlow()
                .Post("{'token_type': 'Bearer', 'access_token': 'wa-wa-wee-wa', 'TwoFactorToken': 'remember-me-token'}")
                .ExpectUrl(IdentityUrl + "/connect/token")
                .ToRestClient(IdentityUrl);

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
                .ExpectUrl(IdentityUrl + "/connect/token")
                .ToRestClient(IdentityUrl);

            Client.RequestAuthToken(Username, PasswordHash, DeviceId, rest);
        }

        [Fact]
        public void RequestAuthToken_sends_device_id()
        {
            var rest = new RestFlow()
                .Post("{'token_type': 'Bearer', 'access_token': 'wa-wa-wee-wa'}")
                .ExpectUrl(IdentityUrl + "/connect/token")
                .ExpectContent("deviceIdentifier=device-id")
                .ToRestClient(IdentityUrl);

            Client.RequestAuthToken(Username, PasswordHash, DeviceId, rest);
        }

        [Fact]
        public void RequestAuthToken_sends_auth_email_header()
        {
            var rest = new RestFlow()
                .Post("{'token_type': 'Bearer', 'access_token': 'wa-wa-wee-wa'}")
                .ExpectUrl(IdentityUrl + "/connect/token")
                .ExpectHeader("Auth-Email", "dXNlcm5hbWU")
                .ToRestClient(IdentityUrl);

            Client.RequestAuthToken(Username, PasswordHash, DeviceId, rest);
        }

        [Fact]
        public void RequestAuthToken_with_second_factor_options_adds_extra_parameters()
        {
            var rest = new RestFlow()
                .Post("{'token_type': 'Bearer', 'access_token': 'wa-wa-wee-wa'}")
                .ExpectUrl(IdentityUrl + "/connect/token")
                .ExpectContent("twoFactorToken=code", "twoFactorProvider=2", "twoFactorRemember=1")
                .ToRestClient(IdentityUrl);

            Client.RequestAuthToken(Username, PasswordHash, DeviceId, new Client.SecondFactorOptions(R.SecondFactorMethod.Duo, "code", true), rest);
        }

        [Fact]
        public void FetchProfile_returns_parsed_response()
        {
            var rest = new RestFlow().Get(GetFixture("profile"));

            var profile = Client.FetchProfile("token", rest);

            Assert.Equal("lastpass.ruby@gmail.com", profile.Email);
        }

        [Fact]
        public void FetchProfile_makes_GET_request_to_specific_endpoint()
        {
            var rest = new RestFlow().Get(GetFixture("profile")).ExpectUrl("/accounts/profile");

            Client.FetchProfile("token", rest);
        }

        [Fact]
        public void FetchProfile_sets_auth_header()
        {
            var rest = new RestFlow()
                .Get(GetFixture("profile"))
                .ExpectUrl(ApiUrl + "/accounts/profile")
                .ExpectHeader("Authorization", "token")
                .ToRestClient(ApiUrl);

            Client.FetchProfile("token", rest);
        }

        [Fact]
        public void FetchVault_returns_parsed_response()
        {
            var rest = new RestFlow().Get(GetFixture("vault")).ExpectUrl(ApiUrl + "/sync").ToRestClient(ApiUrl);

            var response = Client.FetchVault("token", rest);

            Assert.StartsWith("2.XZ2v", response.Profile.Key);
            Assert.Equal(6, response.Ciphers.Length);
            Assert.Equal(2, response.Folders.Length);
        }

        [Fact]
        public void FetchVault_makes_GET_request_to_specific_endpoint()
        {
            var rest = new RestFlow().Get(GetFixture("vault")).ExpectUrl(ApiUrl + "/sync").ToRestClient(ApiUrl);

            Client.FetchVault("token", rest);
        }

        [Fact]
        public void FetchVault_sets_auth_header()
        {
            var rest = new RestFlow()
                .Get(GetFixture("vault"))
                .ExpectUrl(ApiUrl + "/sync")
                .ExpectHeader("Authorization", "token")
                .ToRestClient(ApiUrl);

            Client.FetchVault("token", rest);
        }

        [Theory]
        [InlineData("single-item-login", "e481381f-25ca-4245-845d-a981014d20a6")]
        [InlineData("single-item-ssh-key", "318df280-7880-4e4f-a965-b2e901549751")]
        public void FetchItem_returns_parsed_response(string fixtureName, string expectedId)
        {
            // Arrange
            var rest = new RestFlow().Get(GetFixture(fixtureName)).ExpectUrl(ApiUrl + "/ciphers/item-id").ToRestClient(ApiUrl);
            var session = MakeSession(rest);

            // Act
            var result = Client.FetchItem("item-id", session);

            // Assert
            result.IsT0.ShouldBeTrue();
            result.AsT0.Id.ShouldBe(expectedId);
        }

        [Fact]
        public void FetchItem_returns_not_found_for_missing_item()
        {
            // Arrange
            var rest = new RestFlow()
                .Get(GetFixture("item-not-found"), HttpStatusCode.NotFound)
                .ExpectUrl(ApiUrl + "/ciphers/item-id")
                .ToRestClient(ApiUrl);
            var session = MakeSession(rest);

            // Act
            var result = Client.FetchItem("item-id", session);

            // Assert
            result.IsT1.ShouldBeTrue();
            result.AsT1.ShouldBe(NoItem.NotFound);
        }

        [Fact]
        public void FetchFolders_returns_parsed_response()
        {
            // Arrange
            var rest = new RestFlow()
                .Get(GetFixture("folders"))
                .ExpectUrl(ApiUrl + "/folders")
                .ExpectHeader("Authorization", "Bearer token")
                .ToRestClient(ApiUrl);
            var session = MakeSession(rest);

            // Act
            var folders = Client.FetchFolders(session);

            // Assert
            folders.Length.ShouldBe(2);
            folders[0].Name.ShouldStartWith("2.");
            folders[1].Name.ShouldStartWith("2.");
        }

        [Fact]
        public void FetchCollections_returns_parsed_response()
        {
            // Arrange
            var rest = new RestFlow()
                .Get(GetFixture("collections"))
                .ExpectUrl(ApiUrl + "/collections")
                .ExpectHeader("Authorization", "Bearer token")
                .ToRestClient(ApiUrl);
            var session = MakeSession(rest);

            // Act
            var collections = Client.FetchCollections(session);

            // Assert
            collections.Length.ShouldBe(2);
            collections[0].Name.ShouldStartWith("2.");
            collections[1].Name.ShouldStartWith("2.");
        }

        [Fact]
        public void DecryptVault_returns_accounts()
        {
            var vault = Client.DecryptVault(LoadVaultFixture(), DerivedKek);

            Assert.Equal(3, vault.Accounts.Length);
            Assert.Equal("Facebook", vault.Accounts[0].Name);
            Assert.Equal("Google", vault.Accounts[1].Name);
            Assert.Equal("only name", vault.Accounts[2].Name);

            Assert.Empty(vault.ParseErrors);
        }

        [Fact]
        public void DecryptVault_returns_ssh_keys()
        {
            var vault = Client.DecryptVault(LoadVaultFixture("vault-with-ssh-keys"), DerivedKek);

            Assert.Equal(5, vault.SshKeys.Length);
            Assert.Equal("318df280-7880-4e4f-a965-b2e901549751", vault.SshKeys[0].Id);
            Assert.Equal("c30a73d5-dae6-4c8a-ba77-b2e901547392", vault.SshKeys[1].Id);
            Assert.Equal("f11504c5-7533-433d-95b1-b2e90154b77f", vault.SshKeys[2].Id);

            Assert.Empty(vault.ParseErrors);
        }

        [Fact]
        public void DecryptVault_returns_collections()
        {
            var vault = Client.DecryptVault(LoadVaultFixture("vault-with-collections"), KekForVaultWithCollections);

            Assert.Equal(2, vault.Collections.Length);

            Assert.Equal("b06e01d8-ae76-4c15-a6ff-ae6d00ce6c88", vault.Collections[0].Id);
            Assert.Equal("Default Collection", vault.Collections[0].Name);
            Assert.Equal("195d27a0-82b0-4259-a8e2-ae6d00ce6c85", vault.Collections[0].OrganizationId);
            Assert.False(vault.Collections[0].HidePasswords);

            Assert.Equal("0db9fc3b-3eb2-4af0-bf0d-ae6d00ce87b5", vault.Collections[1].Id);
            Assert.Equal("Hidden pwd", vault.Collections[1].Name);
            Assert.Equal("195d27a0-82b0-4259-a8e2-ae6d00ce6c85", vault.Collections[1].OrganizationId);
            Assert.True(vault.Collections[1].HidePasswords);
        }

        [Fact]
        public void DecryptVault_returns_organizations()
        {
            var vault = Client.DecryptVault(LoadVaultFixture("vault-with-collections"), KekForVaultWithCollections);

            Assert.Equal(2, vault.Organizations.Length);

            Assert.Equal("487e674f-7b11-4b33-9d1a-adb2007f6a6a", vault.Organizations[0].Id);
            Assert.Equal("Gobias Industries Inc", vault.Organizations[0].Name);

            Assert.Equal("195d27a0-82b0-4259-a8e2-ae6d00ce6c85", vault.Organizations[1].Id);
            Assert.Equal("Free Sharing Corp", vault.Organizations[1].Name);
        }

        [Fact]
        public void DecryptVault_assigns_folders()
        {
            var vault = Client.DecryptVault(LoadVaultFixture(), DerivedKek);

            Assert.Equal("Facebook", vault.Accounts[0].Name);
            Assert.Equal("folder2", vault.Accounts[0].Folder);

            Assert.Equal("Google", vault.Accounts[1].Name);
            Assert.Equal("", vault.Accounts[1].Folder);

            Assert.Equal("only name", vault.Accounts[2].Name);
            Assert.Equal("folder1", vault.Accounts[2].Folder);
        }

        [Fact]
        public void DecryptVault_resolves_HidePassword_with_no_collections()
        {
            var vault = Client.DecryptVault(LoadVaultFixture(), DerivedKek);

            Assert.Equal(3, vault.Accounts.Length);
            Assert.False(vault.Accounts[0].HidePassword);
            Assert.False(vault.Accounts[1].HidePassword);
            Assert.False(vault.Accounts[2].HidePassword);
        }

        [Fact]
        public void DecryptVault_assigns_collections_and_resolves_HidePassword()
        {
            var vault = Client.DecryptVault(LoadVaultFixture("vault-with-collections"), KekForVaultWithCollections);

            Assert.Equal(3, vault.Accounts.Length);

            Assert.Equal("both", vault.Accounts[0].Name);
            Assert.Equal(new[] { "b06e01d8-ae76-4c15-a6ff-ae6d00ce6c88", "0db9fc3b-3eb2-4af0-bf0d-ae6d00ce87b5" }, vault.Accounts[0].CollectionIds);
            Assert.False(vault.Accounts[0].HidePassword);

            Assert.Equal("hiddenonly", vault.Accounts[1].Name);
            Assert.Equal(new[] { "0db9fc3b-3eb2-4af0-bf0d-ae6d00ce87b5" }, vault.Accounts[1].CollectionIds);
            Assert.True(vault.Accounts[1].HidePassword);

            Assert.Equal("defonly", vault.Accounts[2].Name);
            Assert.Equal(new[] { "b06e01d8-ae76-4c15-a6ff-ae6d00ce6c88" }, vault.Accounts[2].CollectionIds);
            Assert.False(vault.Accounts[2].HidePassword);
        }

        [Fact]
        public void DecryptVault_returns_errors()
        {
            var vault = Client.DecryptVault(LoadVaultFixture("vault-with-errors"), DerivedKek);

            Assert.NotEmpty(vault.Accounts);
            Assert.NotEmpty(vault.ParseErrors);
        }

        [Fact]
        public void ParseAccountItem_returns_account()
        {
            var vault = LoadVaultFixture();
            var account = Client.ParseAccountItem(vault.Ciphers[0], VaultKey, null, Folders, new Dictionary<string, Collection>());

            Assert.Equal("a323db80-891a-4d91-9304-a981014cf3ca", account.Id);
            Assert.Equal("Facebook", account.Name);
            Assert.Equal("mark", account.Username);
            Assert.Equal("zuckerberg", account.Password);
            Assert.Equal("https://facebook.com", account.Url);
            Assert.Equal("Hey, check this out!", account.Note);
            Assert.Equal("folder2", account.Folder);
        }

        [Fact]
        public void ParseAccountItemWithFields_returns_account()
        {
            var vault = LoadVaultFixture("vault-with-fields");
            var account = Client.ParseAccountItem(vault.Ciphers[1], VaultKey, null, Folders, new Dictionary<string, Collection>());

            Assert.Equal("e481381f-25ca-4245-845d-a981014d20a6", account.Id);
            Assert.Equal("Google", account.Name);
            Assert.Equal("larry", account.Username);
            Assert.Equal("page", account.Password);
            Assert.Equal("https://google.com", account.Url);
            Assert.Equal("Yo, look at this!", account.Note);
            Assert.Equal("", account.Folder);

            Assert.Equal(10, account.CustomFields.Length);
            Assert.Equal("text1", account.CustomFields[0].Name);
            Assert.Equal("value1", account.CustomFields[0].Value);
            Assert.Equal("hidden1", account.CustomFields[1].Name);
            Assert.Equal("value2", account.CustomFields[1].Value);
            Assert.Equal("boolean1", account.CustomFields[2].Name);
            Assert.Equal("true", account.CustomFields[2].Value);
            Assert.Equal("linked1", account.CustomFields[3].Name);
            Assert.Equal("page", account.CustomFields[3].Value);
            Assert.Equal("linked2", account.CustomFields[4].Name);
            Assert.Equal("larry", account.CustomFields[4].Value);
            Assert.Equal("", account.CustomFields[5].Name);
            Assert.Equal("", account.CustomFields[5].Value);
            Assert.Equal("", account.CustomFields[6].Name);
            Assert.Equal("", account.CustomFields[6].Value);
            Assert.Equal("", account.CustomFields[7].Name);
            Assert.Equal("", account.CustomFields[7].Value);
            Assert.Equal("", account.CustomFields[8].Name);
            Assert.Equal("false", account.CustomFields[8].Value);
            Assert.Equal("", account.CustomFields[9].Name);
            Assert.Equal("page", account.CustomFields[9].Value);
        }

        [Fact]
        public void ParseField_throws_on_invalid_type()
        {
            // Arrange
            var field = new R.Field
            {
                Type = 4,
                Name = null,
                Value = null,
            };

            // Act/Assert
            Exceptions.AssertThrowsUnsupportedFeature(() => Client.ParseField(field, VaultKey, LoginItem), "Custom field type 4");
        }

        [Theory]
        [InlineData(null, "")]
        [InlineData(100, "larry")] // username
        [InlineData(101, "page")] // password
        public void ResolveLinkedField_returns_mapped_value(int? linkedId, string expected)
        {
            // Arrange/Act
            var value = Client.ResolveLinkedField(linkedId, VaultKey, LoginItem);

            // Assert
            value.ShouldBe(expected);
        }

        [Fact]
        public void ResolveLinkedField_throws_on_unsupported_linked_id()
        {
            // Arrange/Act/Assert
            Exceptions.AssertThrowsUnsupportedFeature(() => Client.ResolveLinkedField(5, VaultKey, LoginItem), "Linked field ID 5");
        }

        [Fact]
        public void DecryptToBytes_returns_decrypted_input()
        {
            var plaintext = Client.DecryptToBytes(EncryptedString, VaultKey);
            Assert.Equal(Plaintext.ToBytes(), plaintext);
        }

        [Fact]
        public void DecryptToString_returns_decrypted_input()
        {
            var plaintext = Client.DecryptToString(EncryptedString, VaultKey);
            Assert.Equal(Plaintext, plaintext);
        }

        [Fact]
        public void DecryptToStringOrBlank_returns_decrypted_input()
        {
            var plaintext = Client.DecryptToStringOrBlank(EncryptedString, VaultKey);
            Assert.Equal(Plaintext, plaintext);
        }

        [Fact]
        public void DecryptToStringOrBlank_returns_blank_for_null_input()
        {
            var blank = Client.DecryptToStringOrBlank(null, VaultKey);
            Assert.Equal("", blank);
        }

        [Theory, CombinatorialData]
        public void GetItem_makes_requests_and_returns_vault_item(
            [CombinatorialValues("single-item-login", "single-item-ssh-key")] string fixtureName,
            bool haveItemFolder,
            bool haveSessionFolders,
            bool haveItemCollections,
            bool haveSessionCollections
        )
        {
            // Arrange
            var itemJson = GetFixture(fixtureName);
            var itemModel = JsonConvert.DeserializeObject<R.Item>(itemJson);

            // Simulate no folder situation
            if (!haveItemFolder)
                itemModel.FolderId = null;

            // Simulate no collection situation
            if (!haveItemCollections)
                itemModel.CollectionIds = [];

            var itemId = itemModel.Id;

            var rest = new RestFlow()
                .Get(JsonConvert.SerializeObject(itemModel))
                .ExpectUrl($"/ciphers/{itemId}/details")
                .ExpectHeader("Authorization", "Bearer token");

            // Simulate no cached folders situation
            if (haveItemFolder && !haveSessionFolders)
                rest.Get(GetFixture("folders"));

            // Simulate no cached collections situation
            if (haveItemCollections && !haveSessionCollections)
                rest.Get(GetFixture("collections"));

            var session = MakeSession(rest);

            if (haveSessionFolders)
                session.Folders = Folders;

            if (haveSessionCollections)
                session.Collections = Collections;

            // Act
            var result = Client.GetItem(itemId, session);

            // Assert
            var item = result.Value as VaultItem;
            Assert.NotNull(item);
            Assert.Equal(itemId, item.Id);

            if (haveItemFolder)
                Assert.NotEmpty(item.Folder);
            else
                Assert.Empty(item.Folder);

            if (haveItemCollections)
                Assert.NotEmpty(item.CollectionIds);
            else
                Assert.Empty(item.CollectionIds);

            if (!haveItemFolder && !haveSessionFolders)
                Assert.Null(session.Folders);

            if (!haveItemCollections && !haveSessionCollections)
                Assert.Null(session.Collections);
        }

        [Fact]
        public void GetItem_returns_no_item_on_missing_item()
        {
            // Arrange
            var rest = new RestFlow().Get(GetFixture("item-not-found"), HttpStatusCode.NotFound);

            // Act
            var result = Client.GetItem("missing-item-id", MakeSession(rest));

            // Assert
            Assert.Equal(NoItem.NotFound, result.AsT2);
        }

        [Fact]
        public void GetItem_returns_no_item_on_unsupported_item()
        {
            // Arrange
            var rest = new RestFlow().Get(GetFixture("single-item-card"));

            // Act
            var result = Client.GetItem("unsupported-item-id", MakeSession(rest, [], []));

            // Assert
            Assert.Equal(NoItem.UnsupportedType, result.AsT2);
        }

        [Fact]
        public void GetItem_returns_account_for_login_item()
        {
            // Arrange
            var rest = new RestFlow()
                .Get(GetFixture("single-item-login"))
                .ExpectUrl(ApiUrl + "/ciphers/item-id/details")
                .ExpectHeader("Authorization", "Bearer token")
                .ToRestClient(ApiUrl);

            // Act
            var result = Client.GetItem("item-id", MakeSession(rest, [], []));

            Assert.True(result.IsT0);
            var account = result.AsT0;
            Assert.Equal("e481381f-25ca-4245-845d-a981014d20a6", account.Id);
            Assert.Equal("Google", account.Name);
        }

        [Fact]
        public void GetItem_returns_ssh_key_for_ssh_key_item()
        {
            // Arrange
            var rest = new RestFlow()
                .Get(GetFixture("single-item-ssh-key"))
                .ExpectUrl(ApiUrl + "/ciphers/item-id/details")
                .ExpectHeader("Authorization", "Bearer token")
                .ToRestClient(ApiUrl);

            // Act
            var result = Client.GetItem("item-id", MakeSession(rest, [], []));

            // Assert
            Assert.True(result.IsT1);
            var sshKey = result.AsT1;
            Assert.Equal("318df280-7880-4e4f-a965-b2e901549751", sshKey.Id);
            Assert.Equal("ssh2", sshKey.Name);
        }

        //
        // Helpers
        //

        private class FakeUi : IUi
        {
            public virtual DuoChoice ChooseDuoFactor(DuoDevice[] devices) => throw new System.NotImplementedException();

            public virtual string ProvideDuoPasscode(DuoDevice device) => throw new System.NotImplementedException();

            public virtual void UpdateDuoStatus(DuoStatus status, string text) => throw new System.NotImplementedException();

            public virtual void Close() => throw new System.NotImplementedException();

            public virtual MfaMethod ChooseMfaMethod(MfaMethod[] availableMethods) => throw new System.NotImplementedException();

            public virtual Passcode ProvideGoogleAuthPasscode() => throw new System.NotImplementedException();

            public virtual Passcode ProvideEmailPasscode(string emailHint) => throw new System.NotImplementedException();

            public virtual Passcode ProvideYubiKeyPasscode() => throw new System.NotImplementedException();
        }

        private class GoogleAuthProvidingUi : FakeUi
        {
            public int ChooseMfaMethodCalledTimes { get; private set; }
            public int ProvideGoogleAuthPasscodeCalledTimes { get; private set; }
            public int CloseCalledTimes { get; private set; }

            public override MfaMethod ChooseMfaMethod(MfaMethod[] availableMethods)
            {
                ChooseMfaMethodCalledTimes++;
                return MfaMethod.GoogleAuth;
            }

            public override Passcode ProvideGoogleAuthPasscode()
            {
                ProvideGoogleAuthPasscodeCalledTimes++;
                return new Passcode("123456", false);
            }

            public override void Close()
            {
                CloseCalledTimes++;
            }
        }

        private Session MakeSession(RestClient rest, Dictionary<string, string> folders = null, Dictionary<string, Collection> collections = null) =>
            new("Bearer token", DerivedKek, Profile, rest, rest.Transport) { Folders = folders, Collections = collections };

        private static ISecureStorage SetupSecureStorage(string token)
        {
            return new MemoryStorage(new Dictionary<string, string> { ["remember-me-token"] = token });
        }

        private R.Vault LoadVaultFixture(string name = "vault")
        {
            return JsonConvert.DeserializeObject<R.Vault>(GetFixture(name));
        }

        private R.Profile LoadProfileFixture(string name = "profile")
        {
            return JsonConvert.DeserializeObject<R.Profile>(GetFixture(name));
        }

        //
        // Data
        //

        private const string ApiUrl = "https://api.bitwarden.com";
        private const string IdentityUrl = "https://identity.bitwarden.com";

        private const string Username = "username";
        private const string ClientId = "client-id";
        private const string ClientSecret = "client-secret";
        private const string DeviceId = "device-id";
        private const string RememberMeToken = "remember-me-token";
        private static readonly byte[] PasswordHash = "password-hash".ToBytes();
        private static readonly byte[] DerivedKek = "SLBgfXoityZsz4ZWvpEPULPZMYGH6vSqh3PXTe5DmyM=".Decode64();
        private static readonly byte[] VaultKey =
            "7Zo+OWHAKzu+Ovxisz38Na4en13SnoKHPxFngLUgLiHzSZCWbq42Mohdr6wInwcsWbbezoVaS2vwZlSlB6G7Mg==".Decode64();
        private static readonly byte[] KekForVaultWithCollections = "zTrKlq/dviZ7aFFyRLDdT8Zju2rRM80+NzDtCl4hvlc=".Decode64();

        private const string EncryptedString =
            "2.8RPqQRT3z5dTQtNAE/2XWw==|cl1uG8jueR0kxPPklGjVJAGCJqaw+YwmDPyNJtIwsXg=|klc2vOsbPPZD5K1MDMf/nqSNLBrOMPVUNycgCgl6l44=";
        private const string Plaintext = "Hey, check this out!";

        private static readonly R.Item LoginItem =
            new()
            {
                Login = new R.LoginInfo
                {
                    Username = "2.VljekSAM8OlXrGeo3feg4g==|zWnkxbTOPwRhq8w549i94Q==|Un5VXCsoowbqBvIMHqxzF1As5LV6LVuZTXyoJGiNkrU=",
                    Password = "2.p/TTcAaZh3YdXjsUGv+UIA==|zzvBs2YffTZhK1GeWwncKQ==|84h3MIjJslUuOZkWJKdMkfRxOwDmKLsujnA7Q95jhF0=",
                },
            };

        private static readonly Dictionary<string, Organization> Organizations =
            new()
            {
                ["d9e85d3d-72bb-4269-a50d-b2ea00bf3505"] = new Organization(id: "d9e85d3d-72bb-4269-a50d-b2ea00bf3505", name: "organization1"),
                ["195d27a0-82b0-4259-a8e2-ae6d00ce6c85"] = new Organization(id: "195d27a0-82b0-4259-a8e2-ae6d00ce6c85", name: "organization2"),
            };

        private static readonly Dictionary<string, byte[]> OrgKeys =
            new()
            {
                ["d9e85d3d-72bb-4269-a50d-b2ea00bf3505"] =
                    "IBu6jMkr2dJRSs2nh0OogrBB/XJ1gRwdoKepo6RJH/fDZhYaF6dHw/PVGPoWiSUDCwZ5eqdFAkEE+poyUock6A==".Decode64(),
                ["195d27a0-82b0-4259-a8e2-ae6d00ce6c85"] =
                    "YJ28tRb4SbLvFcJLsOhh3Ci4a+9d2xesUlV84fVrHPDbIHbm9J+Hko0Hf27GCmM3PFrLmtnf3k8eperdgASHow==".Decode64(),
            };

        private static readonly Profile Profile = new(VaultKey, [], Organizations, OrgKeys);

        private static readonly Dictionary<string, string> Folders =
            new() { ["d0e9210c-610b-4427-a344-a99600d462d3"] = "folder1", ["94542f0a-d858-46ce-87a5-a99600d47732"] = "folder2" };

        private static readonly Dictionary<string, Collection> Collections =
            new()
            {
                ["406cc470-08c9-469c-b4a7-b2ea00bf352b"] = new Collection(
                    id: "406cc470-08c9-469c-b4a7-b2ea00bf352b",
                    name: "collection1",
                    organizationId: "d9e85d3d-72bb-4269-a50d-b2ea00bf3505",
                    hidePasswords: false
                ),
                ["c323c924-420d-45b6-b58e-b2ea00bfb96a"] = new Collection(
                    id: "c323c924-420d-45b6-b58e-b2ea00bfb96a",
                    name: "collection2",
                    organizationId: "d9e85d3d-72bb-4269-a50d-b2ea00bf3505",
                    hidePasswords: false
                ),
            };
    }
}
