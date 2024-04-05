// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Net;
using Newtonsoft.Json;
using PasswordManagerAccess.Common;
using Xunit;
using PasswordManagerAccess.DropboxPasswords;
using R = PasswordManagerAccess.DropboxPasswords.Response;

namespace PasswordManagerAccess.Test.DropboxPasswords
{
    public class ClientTest: TestBase
    {
        [Fact]
        public void CryptoBoxOpenEasy_decrypts_ciphertext()
        {
            var plaintext = Client.CryptoBoxOpenEasy(
                ciphertext: "kDZmVHrS3ZRNZUnUcaKQ6z5KqR5XYY6ymmJLAZhNVJk=".Decode64(),
                nonce: "nSgGUq0+wgk6FuTonn/gLX3tMRYyDEsP".Decode64(),
                ourPrivateKey: "EDrBprqwud8YbZ10T0/7JmDcQY1tKWDmUFNqV8bw5k0=".Decode64(),
                theirPublicKey: "1YPKexhpTXpqx9WQC2rfQ19qg1SD27jKkv8Iu2CqZU4=".Decode64());

            Assert.Equal("043edb6f0d6da92fe4dca929684dadcf".DecodeHex(), plaintext);
        }

        [Fact]
        public void OpenVault_with_bolt_returns_accounts()
        {
            var flow = new RestFlow()
                .Post(GetFixture("account-info"))
                .Post(GetFixture("features"))
                .Post(GetFixture("root-folder"))
                .Post(GetFixture("entry-keyset"))
                .Post(GetFixture("entry-vault"));

            var account = Client.OpenVault(ClientInfo, Array.Empty<string>(), null, GetStorage(), flow);
            Assert.NotEmpty(account);
        }

        [Fact]
        public void OpenVault_throws_on_server_errors_at_any_step()
        {
            var fixtures = new[] {"account-info", "features", "root-folder", "entry-keyset", "entry-vault"};
            foreach (var failOnFixture in fixtures)
            {
                var flow = new RestFlow();
                foreach (var fixture in fixtures)
                    if (fixture == failOnFixture)
                        flow.Post("", HttpStatusCode.NotFound);
                    else
                        flow.Post(GetFixture(fixture));

                Exceptions.AssertThrowsInternalError(() => Client.OpenVault(ClientInfo, Array.Empty<string>(), null, GetStorage(), flow));
            }
        }

        [Fact]
        public void OpenVault_restarts_on_expired_token_at_any_step_performs_oauth_and_sets_new_token()
        {
            var fixtures = new[] {"account-info", "features", "root-folder", "entry-keyset", "entry-vault"};
            foreach (var failOnFixture in fixtures)
            {
                var flow = new RestFlow();
                foreach (var fixture in fixtures)
                {
                    if (fixture == failOnFixture)
                    {
                        // Add an expired token response
                        flow.Post(GetFixture("expired-oauth"), HttpStatusCode.Unauthorized);

                        // Add OAuth steps
                        flow.Post(GetFixture("code-for-oauth-exchange"));

                        // And the all the steps once again
                        foreach (var f in fixtures)
                            flow.Post(GetFixture(f));

                        break;
                    }

                    flow.Post(GetFixture(fixture));
                }

                var storage = GetStorage();
                var accounts = Client.OpenVault(ClientInfo, Array.Empty<string>(), GetUi(), storage, flow);

                Assert.NotEmpty(accounts);
                Assert.Equal(OAuthToken, storage.Values["oauth-token"]);
            }
        }

        [Fact]
        public void OpenVault_without_oauth_token_opens_browser()
        {
            var flow = new RestFlow()
                .Post(GetFixture("code-for-oauth-exchange"))
                .Post(GetFixture("account-info"))
                .Post(GetFixture("features"))
                .Post(GetFixture("root-folder"))
                .Post(GetFixture("entry-keyset"))
                .Post(GetFixture("entry-vault"));

            var storage = GetStorage();
            storage.Values.Remove("oauth-token");

            var accounts = Client.OpenVault(ClientInfo, Array.Empty<string>(), GetUi(), storage, flow);

            Assert.NotEmpty(accounts);
            Assert.Equal(OAuthToken, storage.Values["oauth-token"]);
        }

        [Fact]
        public void OpenVault_with_recovery_words_returns_accounts()
        {
            var flow = new RestFlow()
                .Post(GetFixture("account-info"))
                .Post(GetFixture("features"))
                .Post(GetFixture("root-folder"))
                .Post(GetFixture("entry-keyset"))
                .Post(GetFixture("entry-vault"));

            var words = new string[]
            {
                "aerobic", "walnut", "swift", "bracket", "surround",
                "obey", "nature", "news", "city", "draw",
                "hidden", "paper"
            };

            var accounts = Client.OpenVault(ClientInfo, UtilTest.RecoveryWords, GetUi(), GetStorage(), flow);

            Assert.Equal(2, accounts.Length);

            var a0 = accounts[0];
            Assert.Equal("7793c55f-6a21-40f5-bb1c-fd175e2515f0", a0.Id);
            Assert.Equal("Facebook", a0.Name);
            Assert.Equal("mark", a0.Username);
            Assert.Equal("yo-yo-yo-yo", a0.Password);
            Assert.Equal("https://facebook.com", a0.Url);
            Assert.Equal("Hey-ya!", a0.Note);
            Assert.Equal("My passwords", a0.Folder);

            var a1 = accounts[1];
            Assert.Equal("df1a3eb0-522a-4acb-a0e6-071fcf295f79", a1.Id);
            Assert.Equal("Google", a1.Name);
            Assert.Equal("blah@gmail.com", a1.Username);
            Assert.Equal("123", a1.Password);
            Assert.Equal("https://https://accounts.google.com/ServiceLogin", a1.Url);
            Assert.Equal("", a1.Note);
            Assert.Equal("My passwords", a1.Folder);
        }

        [Fact]
        public void FindAndDecryptAllKeysets_returns_only_keysets()
        {
            var entries = JsonConvert.DeserializeObject<R.EncryptedEntry[]>(GetFixture("entries"));
            var keysets = Client.FindAndDecryptAllKeysets(entries, MasterKey);

            Assert.Single(keysets);
        }

        //
        // Helpers
        //

        private class OAuthPerformingUi: IUi
        {
            public string PerformOAuthLogin(string url, string redirectUrl)
            {
                return "https://www.dropbox.com/passwords_extension/auth_redirect?code=code";
            }

            public void EnrollRequestSent(string[] deviceNames)
            {
            }
        }

        private static IUi GetUi()
        {
            return new OAuthPerformingUi();
        }

        private static MemoryStorage GetStorage()
        {
            return new MemoryStorage(new Dictionary<string, string>
            {
                ["oauth-token"] = "oauth-token",
                ["master-key"] = UtilTest.MasterKey.ToBase64(),
            });
        }

        //
        // Data
        //

        // TODO: Share with UtilTest
        private static readonly byte[] MasterKey =
            "4a0a046a2d4e2ee312c550a54fe96b573133e0d5b34f09b985c2b02876b98e6f".DecodeHex();

        private const string OAuthToken = "SpEDMQTeZlUAAAAAAAAAAVWWS95lD7vRptHu5Prl9NA02kM5PsdBhY--QBpOexA8";

        private static readonly ClientInfo ClientInfo = new ClientInfo("device-id", "device-name");
    }
}
