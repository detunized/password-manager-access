// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using Bitwarden.Response;
using Moq;
using Newtonsoft.Json;
using NUnit.Framework;

namespace Bitwarden.Test
{
    [TestFixture]
    public class ClientTest
    {
        [Test]
        public void RequestKdfIterationCount_returns_iteration_count()
        {
            var count = Client.RequestKdfIterationCount(Username, SetupKdfRequest());

            Assert.That(count, Is.EqualTo(1337));
        }

        [Test]
        public void RequestKdfIterationCount_makes_POST_request_to_specific_endpoint()
        {
            var jsonHttp = SetupKdfRequest();
            Client.RequestKdfIterationCount(Username, jsonHttp);

            JsonHttpClientTest.VerifyPostUrl(jsonHttp, ".com/api/accounts/prelogin");
        }

        [Test]
        public void Login_returns_auth_token_on_non_2fa_login()
        {
            var token = Client.Login(Username, PasswordHash, null, SetupAuthTokenRequest());

            Assert.That(token, Is.EqualTo("Bearer wa-wa-wee-wa"));
        }

        [Test]
        public void RequestAuthToken_returns_auth_token_response()
        {
            var response = Client.RequestAuthToken(Username, PasswordHash, SetupAuthTokenRequest());

            Assert.That(response.AuthToken, Is.EqualTo("Bearer wa-wa-wee-wa"));
            Assert.That(response.SecondFactor.Methods, Is.Null);
        }

        [Test]
        public void RequestAuthToken_makes_POST_request_to_specific_endpoint()
        {
            var jsonHttp = SetupAuthTokenRequest();
            Client.RequestAuthToken(Username, PasswordHash, jsonHttp);

            JsonHttpClientTest.VerifyPostUrl(jsonHttp, ".com/identity/connect/token");
        }

        [Test]
        public void RequestAuthToken_with_second_factor_options_adds_extra_parameters()
        {
            var jsonHttp = SetupAuthTokenRequest();
            Client.RequestAuthToken(Username,
                                    PasswordHash,
                                    new Client.SecondFactorOptions(SecondFactorMethod.Duo, "code"),
                                    jsonHttp);

            Mock.Get(jsonHttp.Http).Verify(x => x.Post(
                It.IsAny<string>(),
                It.Is<string>(s => s.Contains("twoFactorToken=code") && s.Contains("twoFactorProvider=2")),
                It.IsAny<Dictionary<string, string>>()));
        }

        [Test]
        public void DownloadVault_returns_parsed_response()
        {
            var jsonHttp = SetupDownloadVault();
            var response = Client.DownloadVault(jsonHttp);

            Assert.That(response.Profile.Key, Is.StringStarting("2.XZ2v"));
            Assert.That(response.Ciphers.Length, Is.EqualTo(6));
            Assert.That(response.Folders.Length, Is.EqualTo(2));
        }

        [Test]
        public void DownloadVault_makes_GET_request_to_specific_endpoint()
        {
            var jsonHttp = SetupDownloadVault();
            Client.DownloadVault(jsonHttp);

            JsonHttpClientTest.VerifyGetUrl(jsonHttp, ".com/api/sync");
        }

        [Test]
        public void DecryptVault_returns_accounts()
        {
            var accounts = Client.DecryptVault(LoadVaultFixture(), Kek);

            Assert.That(accounts.Length, Is.EqualTo(3));
            Assert.That(accounts[0].Name, Is.EqualTo("Facebook"));
            Assert.That(accounts[1].Name, Is.EqualTo("Google"));
            Assert.That(accounts[2].Name, Is.EqualTo("only name"));
        }

        [Test]
        public void DecryptVault_assigns_folders()
        {
            var accounts = Client.DecryptVault(LoadVaultFixture(), Kek);

            Assert.That(accounts[0].Name, Is.EqualTo("Facebook"));
            Assert.That(accounts[0].Folder, Is.EqualTo("folder2"));

            Assert.That(accounts[1].Name, Is.EqualTo("Google"));
            Assert.That(accounts[1].Folder, Is.EqualTo(""));

            Assert.That(accounts[2].Name, Is.EqualTo("only name"));
            Assert.That(accounts[2].Folder, Is.EqualTo("folder1"));
        }

        [Test]
        public void ParseAccountItem_returns_account()
        {
            var vault = LoadVaultFixture();
            var folders = new Dictionary<string, string>
            {
                {"d0e9210c-610b-4427-a344-a99600d462d3", "folder1"},
                {"94542f0a-d858-46ce-87a5-a99600d47732", "folder2"},
            };
            var account = Client.ParseAccountItem(vault.Ciphers[0], Key, folders);

            Assert.That(account.Id, Is.EqualTo("a323db80-891a-4d91-9304-a981014cf3ca"));
            Assert.That(account.Name, Is.EqualTo("Facebook"));
            Assert.That(account.Username, Is.EqualTo("mark"));
            Assert.That(account.Password, Is.EqualTo("zuckerberg"));
            Assert.That(account.Url, Is.EqualTo("https://facebook.com"));
            Assert.That(account.Note, Is.EqualTo("Hey, check this out!"));
            Assert.That(account.Folder, Is.EqualTo("folder2"));
        }

        [Test]
        public void DecryptToBytes_returns_decrypted_input()
        {
            var plaintext = Client.DecryptToBytes(EncryptedString, Key);
            Assert.That(plaintext, Is.EqualTo(Plaintext.ToBytes()));
        }

        [Test]
        public void DecryptToString_returns_decrypted_input()
        {
            var plaintext = Client.DecryptToString(EncryptedString, Key);
            Assert.That(plaintext, Is.EqualTo(Plaintext));
        }

        [Test]
        public void DecryptToStringOrBlank_returns_decrypted_input()
        {
            var plaintext = Client.DecryptToStringOrBlank(EncryptedString, Key);
            Assert.That(plaintext, Is.EqualTo(Plaintext));
        }

        [Test]
        public void DecryptToStringOrBlank_returns_blank_for_null_input()
        {
            var blank = Client.DecryptToStringOrBlank(null, Key);
            Assert.That(blank, Is.EqualTo(""));
        }

        //
        // Helpers
        //

        private static JsonHttpClient SetupKdfRequest()
        {
            return SetupPost("{'Kdf': 0, 'KdfIterations': 1337}");
        }

        private static JsonHttpClient SetupAuthTokenRequest()
        {
            return SetupPost("{'token_type': 'Bearer', 'access_token': 'wa-wa-wee-wa'}");
        }

        private static JsonHttpClient SetupDownloadVault()
        {
            return SetupGetWithFixture("vault");
        }

        private static JsonHttpClient SetupGetWithFixture(string name)
        {
            return MakeJsonHttp(JsonHttpClientTest.SetupGetWithFixture(name));
        }

        private static JsonHttpClient SetupPost(string response)
        {
            return MakeJsonHttp(JsonHttpClientTest.SetupPost(response));
        }

        private static JsonHttpClient MakeJsonHttp(Mock<IHttpClient> http)
        {
            return new JsonHttpClient(http.Object, "https://vault.bitwarden.com");
        }

        private static Response.Vault LoadVaultFixture()
        {
            return JsonConvert.DeserializeObject<Response.Vault>(JsonHttpClientTest.ReadFixture("vault"));
        }

        //
        // Data
        //

        private const string Username = "username";
        private static readonly byte[] PasswordHash = "password-hash".ToBytes();
        private static readonly byte[] Kek = "SLBgfXoityZsz4ZWvpEPULPZMYGH6vSqh3PXTe5DmyM=".Decode64();
        private static readonly byte[] Key = "7Zo+OWHAKzu+Ovxisz38Na4en13SnoKHPxFngLUgLiHzSZCWbq42Mohdr6wInwcsWbbezoVaS2vwZlSlB6G7Mg==".Decode64();

        private const string EncryptedString = "2.8RPqQRT3z5dTQtNAE/2XWw==|cl1uG8jueR0kxPPklGjVJAGCJqaw+YwmDPyNJtIwsXg=|klc2vOsbPPZD5K1MDMf/nqSNLBrOMPVUNycgCgl6l44=";
        private const string Plaintext = "Hey, check this out!";
    }
}
