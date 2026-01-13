// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Net;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using PasswordManagerAccess.Bitwarden;
using PasswordManagerAccess.Common;
using Shouldly;
using Xunit;

namespace PasswordManagerAccess.Test.Bitwarden
{
    public class ClientTest : TestBase
    {
        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void MakeRestClient_throws_on_null_or_empty_base_url(string baseUrl)
        {
            // Arrange
            var act = () => Client.MakeRestClient(baseUrl, new RestFlow());

            // Act
            var ex = Should.Throw<ArgumentException>(act);

            // Assert
            ex.Message.ShouldContain("Base URL must not be null or empty");
        }

        [Theory]
        [InlineData("https://base.url")]
        [InlineData("https://base.url/")]
        public void MakeRestClient_sets_base_url_without_trailing_slash(string baseUrl)
        {
            // Arrange/Act
            var rest = Client.MakeRestClient(baseUrl, new RestFlow());

            // Assert
            rest.BaseUrl.ShouldBe("https://base.url");
        }

        [Fact]
        public async Task RequestAuthInfo_makes_POST_request_to_specific_endpoint_and_returns_result_pbdkf2()
        {
            // Arrange
            var rest = new RestFlow { UseSystemJson = true }
                .Post(
                    """{"token_type":"Bearer","access_token":"wa-wa-wee-wa","expires_in":3600,"Kdf":0,"KdfIterations":1337,"KdfMemory":null,"KdfParallelism":null}"""
                )
                .ExpectUrl(BaseUrl + "/identity/connect/token")
                .ToRestClient(BaseUrl);

            // Act
            var authInfo = await Client.RequestAuthInfo(ClientId, DeviceId, [], rest, DefaultCt);

            // Assert
            authInfo.AuthToken.ShouldBe("Bearer wa-wa-wee-wa");
            authInfo.KdfInfo.Kdf.ShouldBe(Model.KdfMethod.Pbkdf2Sha256);
            authInfo.KdfInfo.Iterations.ShouldBe(1337);
        }

        [Fact]
        public async Task RequestAuthInfo_makes_POST_request_to_specific_endpoint_and_returns_result_argon2id()
        {
            // Arrange
            var rest = new RestFlow { UseSystemJson = true }
                .Post(
                    """{"token_type":"Bearer","access_token":"wa-wa-wee-wa","expires_in":3600,"Kdf":1,"KdfIterations":3,"KdfMemory":64,"KdfParallelism":4}"""
                )
                .ExpectUrl(BaseUrl + "/identity/connect/token")
                .ToRestClient(BaseUrl);

            // Act
            var authInfo = await Client.RequestAuthInfo(ClientId, DeviceId, [], rest, DefaultCt);

            // Assert
            authInfo.AuthToken.ShouldBe("Bearer wa-wa-wee-wa");
            authInfo.KdfInfo.Kdf.ShouldBe(Model.KdfMethod.Argon2id);
            authInfo.KdfInfo.Iterations.ShouldBe(3);
            authInfo.KdfInfo.Memory.ShouldBe(64);
            authInfo.KdfInfo.Parallelism.ShouldBe(4);
        }

        [Fact]
        public async Task RequestAuthInfo_throws_on_unsupported_kdf()
        {
            // Arrange
            var rest = new RestFlow { UseSystemJson = true }
                .Post(
                    """{"token_type":"Bearer","access_token":"wa-wa-wee-wa","expires_in":3600,"Kdf":13,"KdfIterations":1337,"KdfMemory":null,"KdfParallelism":null}"""
                )
                .ToRestClient(BaseUrl);
            var act = async () => await Client.RequestAuthInfo(ClientId, DeviceId, [], rest, DefaultCt);

            // Act
            var ex = await act.ShouldThrowAsync<UnsupportedFeatureException>();

            // Assert
            ex.Message.ShouldContain("KDF method");
        }

        [Fact]
        public async Task RequestAuthInfo_throws_on_incorrect_client_credentials()
        {
            // Arrange
            var rest = new RestFlow { UseSystemJson = true }
                .Post("""{"error":"invalid_client"}""", status: HttpStatusCode.BadRequest)
                .ExpectUrl(BaseUrl + "/identity/connect/token")
                .ToRestClient(BaseUrl);
            var act = async () => await Client.RequestAuthInfo(ClientId, DeviceId, [], rest, DefaultCt);

            // Act
            var ex = await act.ShouldThrowAsync<BadCredentialsException>();

            // Assert
            ex.Message.ShouldContain("Client ID or secret is incorrect");
        }

        [Fact]
        public async Task FetchProfile_returns_parsed_response()
        {
            // Arrange
            var rest = new RestFlow { UseSystemJson = true }.Get(GetFixture("profile"));

            // Act
            var profile = await Client.FetchProfile(rest, DefaultCt);

            // Assert
            profile.Email.ShouldBe("lastpass.ruby@gmail.com");
        }

        [Fact]
        public async Task FetchProfile_makes_GET_request_to_specific_endpoint()
        {
            // Arrange
            var rest = new RestFlow { UseSystemJson = true }
                .Get(GetFixture("profile"))
                .ExpectUrl("/accounts/profile");

            // Act/Assert
            await Client.FetchProfile(rest, DefaultCt);
        }

        [Fact]
        public async Task FetchProfile_sets_auth_header()
        {
            // Arrange
            var rest = new RestFlow { UseSystemJson = true }
                .Get(GetFixture("profile"))
                .ExpectUrl(BaseUrl + "/api/accounts/profile")
                .ToRestClient(BaseUrl);

            // Act/Assert
            await Client.FetchProfile(rest, DefaultCt);
        }

        [Fact]
        public async Task FetchVault_returns_parsed_response()
        {
            // Arrange
            var rest = new RestFlow { UseSystemJson = true }
                .Get(GetFixture("vault"))
                .ExpectUrl(BaseUrl + "/api/sync")
                .ToRestClient(BaseUrl);

            // Act
            var response = await Client.FetchVault(rest, DefaultCt);

            // Assert
            response.Profile.Key.ShouldStartWith("2.XZ2v");
            response.Ciphers.Length.ShouldBe(6);
            response.Folders.Length.ShouldBe(2);
        }

        [Fact]
        public async Task FetchVault_makes_GET_request_to_specific_endpoint()
        {
            // Arrange
            var rest = new RestFlow { UseSystemJson = true }
                .Get(GetFixture("vault"))
                .ExpectUrl(BaseUrl + "/api/sync")
                .ToRestClient(BaseUrl);

            // Act/Assert
            await Client.FetchVault(rest, DefaultCt);
        }

        [Fact]
        public async Task FetchVault_sets_auth_header()
        {
            // Arrange
            var rest = new RestFlow { UseSystemJson = true }
                .Get(GetFixture("vault"))
                .ExpectUrl(BaseUrl + "/api/sync")
                .ToRestClient(BaseUrl);

            // Act/Assert
            await Client.FetchVault(rest, DefaultCt);
        }

        [Theory]
        [InlineData("single-item-login", "e481381f-25ca-4245-845d-a981014d20a6")]
        [InlineData("single-item-ssh-key", "318df280-7880-4e4f-a965-b2e901549751")]
        public async Task FetchItem_returns_parsed_response(string fixtureName, string expectedId)
        {
            // Arrange
            var rest = new RestFlow { UseSystemJson = true }
                .Get(GetFixture(fixtureName))
                .ExpectUrl(BaseUrl + "/api/ciphers/item-id")
                .ToRestClient(BaseUrl);
            var session = MakeSession(rest);

            // Act
            var result = await Client.FetchItem("item-id", session, DefaultCt);

            // Assert
            result.IsT0.ShouldBeTrue();
            result.AsT0.Id.ShouldBe(expectedId);
        }

        [Fact]
        public async Task FetchItem_returns_not_found_for_missing_item()
        {
            // Arrange
            var rest = new RestFlow { UseSystemJson = true }
                .Get(GetFixture("item-not-found"), HttpStatusCode.NotFound)
                .ExpectUrl(BaseUrl + "/api/ciphers/item-id")
                .ToRestClient(BaseUrl);
            var session = MakeSession(rest);

            // Act
            var result = await Client.FetchItem("item-id", session, DefaultCt);

            // Assert
            result.IsT1.ShouldBeTrue();
            result.AsT1.ShouldBe(NoItem.NotFound);
        }

        [Fact]
        public async Task FetchFolders_returns_parsed_response()
        {
            // Arrange
            var rest = new RestFlow { UseSystemJson = true }
                .Get(GetFixture("folders"))
                .ExpectUrl(BaseUrl + "/api/folders")
                .ToRestClient(BaseUrl);
            var session = MakeSession(rest);

            // Act
            var folders = await Client.FetchFolders(session, DefaultCt);

            // Assert
            folders.Length.ShouldBe(2);
            folders[0].Name.ShouldStartWith("2.");
            folders[1].Name.ShouldStartWith("2.");
        }

        [Fact]
        public async Task FetchCollections_returns_parsed_response()
        {
            // Arrange
            var rest = new RestFlow { UseSystemJson = true }
                .Get(GetFixture("collections"))
                .ExpectUrl(BaseUrl + "/api/collections")
                .ToRestClient(BaseUrl);
            var session = MakeSession(rest);

            // Act
            var collections = await Client.FetchCollections(session, DefaultCt);

            // Assert
            collections.Length.ShouldBe(2);
            collections[0].Name.ShouldStartWith("2.");
            collections[1].Name.ShouldStartWith("2.");
        }

        [Fact]
        public void DecryptVault_returns_accounts()
        {
            // Arrange/Act
            var vault = Client.DecryptVault(LoadVaultFixture(), DerivedKek);

            // Assert
            vault.Accounts.Length.ShouldBe(3);
            vault.Accounts[0].Name.ShouldBe("Facebook");
            vault.Accounts[1].Name.ShouldBe("Google");
            vault.Accounts[2].Name.ShouldBe("only name");
            vault.ParseErrors.ShouldBeEmpty();
        }

        [Fact]
        public void DecryptVault_returns_ssh_keys()
        {
            // Arrange/Act
            var vault = Client.DecryptVault(LoadVaultFixture("vault-with-ssh-keys"), DerivedKek);

            // Assert
            vault.SshKeys.Length.ShouldBe(5);
            vault.SshKeys[0].Id.ShouldBe("318df280-7880-4e4f-a965-b2e901549751");
            vault.SshKeys[1].Id.ShouldBe("c30a73d5-dae6-4c8a-ba77-b2e901547392");
            vault.SshKeys[2].Id.ShouldBe("f11504c5-7533-433d-95b1-b2e90154b77f");
            vault.ParseErrors.ShouldBeEmpty();
        }

        [Fact]
        public void DecryptVault_ignores_deleted_items()
        {
            // Arrange/Act
            var vault = Client.DecryptVault(LoadVaultFixture("vault-with-deleted-items"), DerivedKek);

            // Assert
            vault.Accounts.ShouldHaveSingleItem();
            vault.Accounts[0].Id.ShouldBe("16f777ff-8824-45cf-b3db-a9d600007388");
            vault.SshKeys.ShouldHaveSingleItem();
            vault.SshKeys[0].Id.ShouldBe("d1812aab-aae7-4f7e-aab4-b2ea00b9bba7");
            vault.ParseErrors.ShouldBeEmpty();
        }

        [Fact]
        public void DecryptVault_returns_collections()
        {
            // Arrange/Act
            var vault = Client.DecryptVault(LoadVaultFixture("vault-with-collections"), KekForVaultWithCollections);

            // Assert
            vault.Collections.Length.ShouldBe(2);

            vault.Collections[0].Id.ShouldBe("b06e01d8-ae76-4c15-a6ff-ae6d00ce6c88");
            vault.Collections[0].Name.ShouldBe("Default Collection");
            vault.Collections[0].OrganizationId.ShouldBe("195d27a0-82b0-4259-a8e2-ae6d00ce6c85");
            vault.Collections[0].HidePasswords.ShouldBeFalse();

            vault.Collections[1].Id.ShouldBe("0db9fc3b-3eb2-4af0-bf0d-ae6d00ce87b5");
            vault.Collections[1].Name.ShouldBe("Hidden pwd");
            vault.Collections[1].OrganizationId.ShouldBe("195d27a0-82b0-4259-a8e2-ae6d00ce6c85");
            vault.Collections[1].HidePasswords.ShouldBeTrue();
        }

        [Fact]
        public void DecryptVault_returns_organizations()
        {
            // Arrange/Act
            var vault = Client.DecryptVault(LoadVaultFixture("vault-with-collections"), KekForVaultWithCollections);

            // Assert
            vault.Organizations.Length.ShouldBe(2);

            vault.Organizations[0].Id.ShouldBe("487e674f-7b11-4b33-9d1a-adb2007f6a6a");
            vault.Organizations[0].Name.ShouldBe("Gobias Industries Inc");

            vault.Organizations[1].Id.ShouldBe("195d27a0-82b0-4259-a8e2-ae6d00ce6c85");
            vault.Organizations[1].Name.ShouldBe("Free Sharing Corp");
        }

        [Fact]
        public void DecryptVault_assigns_folders()
        {
            // Arrange/Act
            var vault = Client.DecryptVault(LoadVaultFixture(), DerivedKek);

            // Assert
            vault.Accounts[0].Name.ShouldBe("Facebook");
            vault.Accounts[0].Folder.ShouldBe("folder2");

            vault.Accounts[1].Name.ShouldBe("Google");
            vault.Accounts[1].Folder.ShouldBe("");

            vault.Accounts[2].Name.ShouldBe("only name");
            vault.Accounts[2].Folder.ShouldBe("folder1");
        }

        [Fact]
        public void DecryptVault_resolves_HidePassword_with_no_collections()
        {
            // Arrange/Act
            var vault = Client.DecryptVault(LoadVaultFixture(), DerivedKek);

            // Assert
            vault.Accounts.Length.ShouldBe(3);
            vault.Accounts[0].HidePassword.ShouldBeFalse();
            vault.Accounts[1].HidePassword.ShouldBeFalse();
            vault.Accounts[2].HidePassword.ShouldBeFalse();
        }

        [Fact]
        public void DecryptVault_assigns_collections_and_resolves_HidePassword()
        {
            // Arrange/Act
            var vault = Client.DecryptVault(LoadVaultFixture("vault-with-collections"), KekForVaultWithCollections);

            // Assert
            vault.Accounts.Length.ShouldBe(3);

            vault.Accounts[0].Name.ShouldBe("both");
            vault.Accounts[0].CollectionIds.ShouldBe(new[] { "b06e01d8-ae76-4c15-a6ff-ae6d00ce6c88", "0db9fc3b-3eb2-4af0-bf0d-ae6d00ce87b5" });
            vault.Accounts[0].HidePassword.ShouldBeFalse();

            vault.Accounts[1].Name.ShouldBe("hiddenonly");
            vault.Accounts[1].CollectionIds.ShouldBe(new[] { "0db9fc3b-3eb2-4af0-bf0d-ae6d00ce87b5" });
            vault.Accounts[1].HidePassword.ShouldBeTrue();

            vault.Accounts[2].Name.ShouldBe("defonly");
            vault.Accounts[2].CollectionIds.ShouldBe(new[] { "b06e01d8-ae76-4c15-a6ff-ae6d00ce6c88" });
            vault.Accounts[2].HidePassword.ShouldBeFalse();
        }

        [Fact]
        public void DecryptVault_returns_errors()
        {
            // Arrange/Act
            var vault = Client.DecryptVault(LoadVaultFixture("vault-with-errors"), DerivedKek);

            // Assert
            vault.Accounts.ShouldNotBeEmpty();
            vault.ParseErrors.ShouldNotBeEmpty();
        }

        [Fact]
        public void ParseAccountItem_returns_account()
        {
            // Arrange
            var vault = LoadVaultFixture();

            // Act
            var account = Client.ParseAccountItem(vault.Ciphers[0], VaultKey, [], Folders, new Dictionary<string, Collection>());

            // Assert
            account.Id.ShouldBe("a323db80-891a-4d91-9304-a981014cf3ca");
            account.Name.ShouldBe("Facebook");
            account.Username.ShouldBe("mark");
            account.Password.ShouldBe("zuckerberg");
            account.Url.ShouldBe("https://facebook.com");
            account.Note.ShouldBe("Hey, check this out!");
            account.Folder.ShouldBe("folder2");
        }

        [Fact]
        public void ParseAccountItemWithFields_returns_account()
        {
            // Arrange
            var vault = LoadVaultFixture("vault-with-fields");

            // Act
            var account = Client.ParseAccountItem(vault.Ciphers[1], VaultKey, [], Folders, new Dictionary<string, Collection>());

            // Assert
            account.Id.ShouldBe("e481381f-25ca-4245-845d-a981014d20a6");
            account.Name.ShouldBe("Google");
            account.Username.ShouldBe("larry");
            account.Password.ShouldBe("page");
            account.Url.ShouldBe("https://google.com");
            account.Note.ShouldBe("Yo, look at this!");
            account.Folder.ShouldBe("");

            account.CustomFields.Length.ShouldBe(10);
            account.CustomFields[0].Name.ShouldBe("text1");
            account.CustomFields[0].Value.ShouldBe("value1");
            account.CustomFields[1].Name.ShouldBe("hidden1");
            account.CustomFields[1].Value.ShouldBe("value2");
            account.CustomFields[2].Name.ShouldBe("boolean1");
            account.CustomFields[2].Value.ShouldBe("true");
            account.CustomFields[3].Name.ShouldBe("linked1");
            account.CustomFields[3].Value.ShouldBe("page");
            account.CustomFields[4].Name.ShouldBe("linked2");
            account.CustomFields[4].Value.ShouldBe("larry");
            account.CustomFields[5].Name.ShouldBe("");
            account.CustomFields[5].Value.ShouldBe("");
            account.CustomFields[6].Name.ShouldBe("");
            account.CustomFields[6].Value.ShouldBe("");
            account.CustomFields[7].Name.ShouldBe("");
            account.CustomFields[7].Value.ShouldBe("");
            account.CustomFields[8].Name.ShouldBe("");
            account.CustomFields[8].Value.ShouldBe("false");
            account.CustomFields[9].Name.ShouldBe("");
            account.CustomFields[9].Value.ShouldBe("page");
        }

        [Fact]
        public void ParseField_throws_on_invalid_type()
        {
            // Arrange
            var field = new Model.Field
            {
                Type = 4,
                Name = null,
                Value = null,
            };
            var act = () => Client.ParseField(field, VaultKey, LoginItem);

            // Act
            var ex = Should.Throw<UnsupportedFeatureException>(act);

            // Assert
            ex.Message.ShouldContain("Custom field type 4");
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
            // Arrange
            var act = () => Client.ResolveLinkedField(5, VaultKey, LoginItem);

            // Act
            var ex = Should.Throw<UnsupportedFeatureException>(act);

            // Assert
            ex.Message.ShouldContain("Linked field ID 5");
        }

        [Fact]
        public void DecryptToBytes_returns_decrypted_input()
        {
            // Arrange/Act
            var plaintext = Client.DecryptToBytes(EncryptedString, VaultKey);

            // Assert
            plaintext.ShouldBe(Plaintext.ToBytes());
        }

        [Fact]
        public void DecryptToString_returns_decrypted_input()
        {
            // Arrange/Act
            var plaintext = Client.DecryptToString(EncryptedString, VaultKey);

            // Assert
            plaintext.ShouldBe(Plaintext);
        }

        [Fact]
        public void DecryptToStringOrBlank_returns_decrypted_input()
        {
            // Arrange/Act
            var plaintext = Client.DecryptToStringOrBlank(EncryptedString, VaultKey);

            // Assert
            plaintext.ShouldBe(Plaintext);
        }

        [Fact]
        public void DecryptToStringOrBlank_returns_blank_for_null_input()
        {
            // Arrange/Act
            var blank = Client.DecryptToStringOrBlank(null, VaultKey);

            // Assert
            blank.ShouldBe("");
        }

        [Theory, CombinatorialData]
        public async Task GetItem_makes_requests_and_returns_vault_item(
            [CombinatorialValues("single-item-login", "single-item-ssh-key")] string fixtureName,
            bool haveItemFolder,
            bool haveSessionFolders,
            bool haveItemCollections,
            bool haveSessionCollections
        )
        {
            // Arrange
            var itemJson = GetFixture(fixtureName);
            var itemModel = JsonSerializer.Deserialize<Model.Item>(itemJson);

            // Simulate no folder situation
            if (!haveItemFolder)
                itemModel = itemModel with { FolderId = null };

            // Simulate no collection situation
            if (!haveItemCollections)
                itemModel = itemModel with { CollectionIds = [] };

            var itemId = itemModel.Id;

            var rest = new RestFlow { UseSystemJson = true }
                .Get(JsonSerializer.Serialize(itemModel))
                .ExpectUrl($"/ciphers/{itemId}/details");

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
            var result = await Client.GetItem(itemId, session, DefaultCt);

            // Assert
            var item = result.Value as VaultItem;
            item.ShouldNotBeNull();
            item.Id.ShouldBe(itemId);

            if (haveItemFolder)
                item.Folder.ShouldNotBeEmpty();
            else
                item.Folder.ShouldBeEmpty();

            if (haveItemCollections)
                item.CollectionIds.ShouldNotBeEmpty();
            else
                item.CollectionIds.ShouldBeEmpty();

            if (!haveItemFolder && !haveSessionFolders)
                session.Folders.ShouldBeNull();

            if (!haveItemCollections && !haveSessionCollections)
                session.Collections.ShouldBeNull();
        }

        [Fact]
        public async Task GetItem_returns_no_item_on_missing_item()
        {
            // Arrange
            var rest = new RestFlow { UseSystemJson = true }.Get(GetFixture("item-not-found"), HttpStatusCode.NotFound);

            // Act
            var result = await Client.GetItem("missing-item-id", MakeSession(rest), DefaultCt);

            // Assert
            result.AsT2.ShouldBe(NoItem.NotFound);
        }

        [Fact]
        public async Task GetItem_returns_no_item_on_unsupported_item()
        {
            // Arrange
            var rest = new RestFlow { UseSystemJson = true }.Get(GetFixture("single-item-card"));

            // Act
            var result = await Client.GetItem("unsupported-item-id", MakeSession(rest, [], []), DefaultCt);

            // Assert
            result.AsT2.ShouldBe(NoItem.UnsupportedType);
        }

        [Fact]
        public async Task GetItem_returns_account_for_login_item()
        {
            // Arrange
            var rest = new RestFlow { UseSystemJson = true }
                .Get(GetFixture("single-item-login"))
                .ExpectUrl(BaseUrl + "/api/ciphers/item-id/details")
                .ToRestClient(BaseUrl);

            // Act
            var result = await Client.GetItem("item-id", MakeSession(rest, [], []), DefaultCt);

            // Assert
            result.IsT0.ShouldBeTrue();
            var account = result.AsT0;
            account.Id.ShouldBe("e481381f-25ca-4245-845d-a981014d20a6");
            account.Name.ShouldBe("Google");
        }

        [Fact]
        public async Task GetItem_returns_ssh_key_for_ssh_key_item()
        {
            // Arrange
            var rest = new RestFlow { UseSystemJson = true }
                .Get(GetFixture("single-item-ssh-key"))
                .ExpectUrl(BaseUrl + "/api/ciphers/item-id/details")
                .ToRestClient(BaseUrl);

            // Act
            var result = await Client.GetItem("item-id", MakeSession(rest, [], []), DefaultCt);

            // Assert
            result.IsT1.ShouldBeTrue();
            var sshKey = result.AsT1;
            sshKey.Id.ShouldBe("318df280-7880-4e4f-a965-b2e901549751");
            sshKey.Name.ShouldBe("ssh2");
        }

        [Theory]
        [InlineData("single-item-login-deleted")]
        [InlineData("single-item-ssh-key-deleted")]
        public async Task GetItem_returns_no_item_deleted_for_deleted_items(string fixtureName)
        {
            // Arrange
            var rest = new RestFlow { UseSystemJson = true }
                .Get(GetFixture(fixtureName))
                .ExpectUrl(BaseUrl + "/api/ciphers/item-id/details")
                .ToRestClient(BaseUrl);

            // Act
            var result = await Client.GetItem("item-id", MakeSession(rest, [], []), DefaultCt);

            // Assert
            result.IsT2.ShouldBeTrue();
            result.AsT2.ShouldBe(NoItem.Deleted);
        }

        //
        // Helpers
        //

        private static CancellationToken DefaultCt => TestContext.Current.CancellationToken;

        private Session MakeSession(RestClient rest, Dictionary<string, string> folders = null, Dictionary<string, Collection> collections = null) =>
            new(DerivedKek, Profile, new MemoryStorage(), rest, rest.Transport) { Folders = folders, Collections = collections };

        private Model.Vault LoadVaultFixture(string name = "vault")
        {
            return JsonSerializer.Deserialize<Model.Vault>(GetFixture(name));
        }

        //
        // Data
        //

        private const string BaseUrl = "https://vault.bitwarden.com";
        private const string ClientId = "client-id";
        private const string ClientSecret = "client-secret";
        private const string DeviceId = "device-id";
        private static readonly byte[] DerivedKek = "SLBgfXoityZsz4ZWvpEPULPZMYGH6vSqh3PXTe5DmyM=".Decode64();
        private static readonly byte[] VaultKey =
            "7Zo+OWHAKzu+Ovxisz38Na4en13SnoKHPxFngLUgLiHzSZCWbq42Mohdr6wInwcsWbbezoVaS2vwZlSlB6G7Mg==".Decode64();
        private static readonly byte[] KekForVaultWithCollections = "zTrKlq/dviZ7aFFyRLDdT8Zju2rRM80+NzDtCl4hvlc=".Decode64();
        private const string EncryptedString =
            "2.8RPqQRT3z5dTQtNAE/2XWw==|cl1uG8jueR0kxPPklGjVJAGCJqaw+YwmDPyNJtIwsXg=|klc2vOsbPPZD5K1MDMf/nqSNLBrOMPVUNycgCgl6l44=";
        private const string Plaintext = "Hey, check this out!";

        private static readonly Model.Item LoginItem =
            new()
            {
                Id = "test-id",
                Login = new Model.LoginInfo
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

        private static readonly Profile Profile = new(VaultKey, Organizations, OrgKeys);

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
