// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.ZohoVault;
using Xunit;
using R = PasswordManagerAccess.ZohoVault.Response;

namespace PasswordManagerAccess.Test.ZohoVault
{
    public class ClientTest: TestBase
    {
        [Fact]
        public void OpenVault_returns_accounts()
        {
            var flow = new RestFlow()
                .Get("", cookies: OAuthCookies)
                .Post(GetFixture("user-exists-response"))
                .Post("showsuccess('blah',)", cookies: LoginCookies)
                .Get(GetFixture("auth-info-response"))
                .Get(GetFixture("vault-response"))
                .Get(""); // Logout

            var vault = Vault.Open(Username, Password, TestData.Passphrase, null, flow);
            var accounts = vault.Accounts;

            Assert.Equal(2, accounts.Length);

            Assert.Equal("30024000000008008", accounts[0].Id);
            Assert.Equal("facebook", accounts[0].Name);
            Assert.Equal("mark", accounts[0].Username);
            Assert.Equal("zuckerberg", accounts[0].Password);
            Assert.Equal("http://facebook.com", accounts[0].Url);
            Assert.Equal("", accounts[0].Note);

            Assert.Equal("30024000000008013", accounts[1].Id);
            Assert.Equal("microsoft", accounts[1].Name);
            Assert.Equal("bill", accounts[1].Username);
            Assert.Equal("gates", accounts[1].Password);
            Assert.Equal("http://microsoft.com", accounts[1].Url);
            Assert.Equal("", accounts[1].Note);
        }

        [Fact]
        public void OpenVault_returns_shared_accounts()
        {
            var flow = new RestFlow()
                .Get("", cookies: OAuthCookies)
                .Post(GetFixture("user-exists-response"))
                .Post("showsuccess('blah',)", cookies: LoginCookies)
                .Get(GetFixture("auth-info-with-shared-items-response"))
                .Get(GetFixture("vault-with-shared-items-response"))
                .Get(""); // Logout

            var vault = Vault.Open(Username, Password, TestData.Passphrase, null, flow);
            var accounts = vault.Accounts;

            Assert.Single(accounts);

            Assert.Equal("113381000000009016", accounts[0].Id);
            Assert.Equal("Facebook", accounts[0].Name);
            Assert.Equal("mark", accounts[0].Username);
            Assert.Equal("zuckerberg", accounts[0].Password);
            Assert.Equal("https://www.facebook.com", accounts[0].Url);
            Assert.Equal("Yo, bitches!", accounts[0].Note);
        }

        [Fact]
        public void RequestToken_makes_GET_request_and_returns_token()
        {
            var flow = new RestFlow()
                .Get("", cookies: OAuthCookies)
                    .ExpectUrl("https://accounts.zoho.com/oauth/v2/auth?");

            var token = Client.RequestToken(flow);

            Assert.Equal(OAuthCookieValue, token);
        }

        [Fact]
        public void RequestToken_throws_on_missing_cookie()
        {
            var flow = new RestFlow().Get("");

            Exceptions.AssertThrowsInternalError(
                () => Client.RequestToken(flow),
                "cookie is not set by the server");
        }

        [Fact]
        public void GetRegionTld_makes_POST_request_and_returns_tld()
        {
            var flow = new RestFlow()
                .Post(GetFixture("user-exists-response"))
                    .ExpectUrl("signin/v2/lookup");

            var tld = Client.GetRegionTld(Username, OAuthCookieValue, flow);

            Assert.Equal("com", tld);
        }

        [Fact]
        public void GetRegionTld_returns_another_tld()
        {
            var flow = new RestFlow()
                .Post(GetFixture("user-exists-in-another-dc-response"));

            var tld = Client.GetRegionTld(Username, OAuthCookieValue, flow);

            Assert.Equal("eu", tld);
        }

        [Fact]
        public void GetRegionTld_throws_on_unknown_user()
        {
            var flow = new RestFlow()
                .Post(GetFixture("user-does-not-exist-response"));

            Exceptions.AssertThrowsBadCredentials(
                () => Client.GetRegionTld("unknown", OAuthCookieValue, flow),
                "The username is invalid");
        }

        [Fact]
        public void GetRegionTld_throws_on_unknown_error_code()
        {
            var flow = new RestFlow()
                .Post(GetFixture("lookup-unknown-error-response"));

            Exceptions.AssertThrowsInternalError(
                () => Client.GetRegionTld(Username, OAuthCookieValue, flow),
                "Unexpected response");
        }

        [Theory]
        [InlineData("us", "com")]
        [InlineData("eu", "eu")]
        [InlineData("in", "in")]
        [InlineData("au", "com.au")]
        public void DataCenterToTld_returns_tld(string dc, string tld)
        {
            Assert.Equal(tld, Client.DataCenterToTld(dc));
        }

        [Fact]
        public void DataCenterToTld_throws_on_unknown_data_center()
        {
            Exceptions.AssertThrowsUnsupportedFeature(
                () => Client.DataCenterToTld("zx"),
                "Unsupported data center");
        }

        [Fact]
        public void Login_makes_requests_and_returns_server_cookies()
        {
            var flow = new RestFlow()
                .Post("showsuccess('blah',)", cookies: LoginCookies)
                    .ExpectUrl("https://accounts.zoho.com/signin/auth")
                    .ExpectContent($"LOGIN_ID={Username}", $"PASSWORD={Password}", $"iamcsrcoo={OAuthCookieValue}")
                    .ExpectCookie("iamcsr", OAuthCookieValue);

            var cookies = Client.Login(Username, Password, OAuthCookieValue, "com", null, flow);

            Assert.Equal(LoginCookieValue, cookies[LoginCookieName]);
        }

        [Fact]
        public void Login_makes_requests_to_specified_tld()
        {
            var flow = new RestFlow()
                .Post("showsuccess('blah',)", cookies: LoginCookies)
                    .ExpectUrl("https://accounts.zoho.eu/signin/auth");

            Client.Login(Username, Password, OAuthCookieValue, "eu", null, flow);
        }

        [Fact]
        public void Login_throws_on_response_with_failure()
        {
            var flow = new RestFlow()
                .Post("showerror('It failed')");

            Exceptions.AssertThrowsBadCredentials(
                () => Client.Login(Username, Password, OAuthCookieValue, "com", null, flow),
                "most likely the credentials are invalid");
        }

        [Fact]
        public void Logout_makes_request_with_token_to_specific_url()
        {
            var flow = new RestFlow()
                .Get("RESULT=TRUE")
                    .ExpectUrl("https://accounts.zoho.com/logout?")
                    .ExpectCookie(LoginCookieName, LoginCookieValue);

            Client.Logout(LoginCookies, "com", flow);
        }

        [Fact]
        public void Authenticate_returns_key()
        {
            var flow = new RestFlow()
                .Get(GetFixture("auth-info-response"))
                    .ExpectUrl("https://vault.zoho.com/api/json/login?OPERATION_NAME=GET_LOGIN")
                    .ExpectCookie(LoginCookieName, LoginCookieValue);

            var key = Client.Authenticate(TestData.Passphrase, LoginCookies, "com", flow);

            Assert.Equal(TestData.Key, key);
        }

        [Fact]
        public void Authenticate_throws_on_incorrect_passphrase()
        {
            var flow = new RestFlow()
                .Get(GetFixture("auth-info-response"));

            Exceptions.AssertThrowsBadCredentials(
                () => Client.Authenticate("Not really a passphrase", LoginCookies, "com", flow),
                "Passphrase is incorrect");
        }

        [Fact]
        public void DownloadVault_makes_GET_request_to_specific_url_and_returns_vault_records()
        {
            var flow = new RestFlow()
                .Get(GetFixture("vault-response"))
                .ExpectUrl("https://vault.zoho.com/api/json/login?OPERATION_NAME=OPEN_VAULT");

            var vault = Client.DownloadVault(LoginCookies, "com", flow);

            Assert.NotEmpty(vault.Secrets);
        }

        [Fact]
        public void DecryptSharingKey_returns_null_when_no_key_is_present()
        {
            var vault = ParseFixture<R.ResponseEnvelope<R.Vault>>("vault-response").Payload;

            Assert.Null(Client.DecryptSharingKey(vault, TestData.Key));
        }

        [Fact]
        public void DecryptSharingKey_returns_key()
        {
            var vault = ParseFixture<R.ResponseEnvelope<R.Vault>>("vault-with-shared-items-response").Payload;

            var sharingKey = Client.DecryptSharingKey(vault, TestData.Key2).ToUtf8();

            Assert.Equal("ItaDMKNE|x4gu1gEom9f@'GWsjH!}$OS", sharingKey);
        }

        [Fact]
        public void GetAuthInfo_makes_GET_request_to_specific_url_and_returns_auth_info()
        {
            var flow = new RestFlow()
                .Get(GetFixture("auth-info-response"))
                    .ExpectUrl("https://vault.zoho.com/api/json/login?OPERATION_NAME=GET_LOGIN")
                    .ExpectCookie(LoginCookieName, LoginCookieValue);

            var info = Client.GetAuthInfo(LoginCookies, "com", flow);

            Assert.Equal(1000, info.IterationCount);
            Assert.Equal("f78e6ffce8e57501a02c9be303db2c68".ToBytes(), info.Salt);
            Assert.Equal("awNZM8agxVecKpRoC821Oq6NlvVwm6KpPGW+cLdzRoc2Mg5vqPQzoONwww==".Decode64(),
                         info.EncryptionCheck);
        }

        [Fact]
        public void ExtractSwitchToUrl_decodes_url()
        {
            var encoded = "switchto('https\\x3A\\x2F\\x2Faccounts.zoho.com\\x2Ftfa\\x2Fauth" +
                          "\\x3Fserviceurl\\x3Dhttps\\x253A\\x252F\\x252Fvault.zoho.com');";

            var url = Client.ExtractSwitchToUrl(encoded);

            Assert.Equal("https://accounts.zoho.com/tfa/auth?serviceurl=https%3A%2F%2Fvault.zoho.com", url);
        }

        private const string Username = "lebowski";
        private const string Password = "logjammin";

        private const string OAuthCookieName = "iamcsr";
        private const string OAuthCookieValue = "iamcsr-blah";

        private const string LoginCookieName = "login-cookie";
        private const string LoginCookieValue = "login-keks";

        private static readonly Dictionary<string, string> OAuthCookies =
            new Dictionary<string, string> { { OAuthCookieName, OAuthCookieValue } };

        private static readonly Dictionary<string, string> LoginCookies =
            new Dictionary<string, string> { { LoginCookieName, LoginCookieValue } };
    }
}
