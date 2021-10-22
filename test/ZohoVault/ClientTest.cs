// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using Moq;
using Newtonsoft.Json;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.ZohoVault;
using PasswordManagerAccess.ZohoVault.Ui;
using Xunit;
using R = PasswordManagerAccess.ZohoVault.Response;

namespace PasswordManagerAccess.Test.ZohoVault
{
    // TODO: Add more MFA tests
    public class ClientTest: TestBase
    {
        [Fact]
        public void OpenVault_returns_accounts()
        {
            var flow = new RestFlow()
                .Get("", cookies: OAuthCookies)
                .Post(GetFixture("lookup-success-response"))
                .Post(GetFixture("login-success-response"), cookies: LoginCookies)
                .Get(GetFixture("auth-info-response"))
                .Get(GetFixture("vault-response"))
                .Get(""); // Logout

            var vault = Vault.Open(Username, Password, TestData.Passphrase, null, GetSecureStorage(), flow);
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
                .Post(GetFixture("lookup-success-response"))
                .Post(GetFixture("login-success-response"), cookies: LoginCookies)
                .Get(GetFixture("auth-info-with-shared-items-response"))
                .Get(GetFixture("vault-with-shared-items-response"))
                .Get(""); // Logout

            var vault = Vault.Open(Username, Password, TestData.Passphrase, null, GetSecureStorage(), flow);
            var accounts = vault.Accounts;

            Assert.Single(accounts);

            Assert.Equal("113381000000009016", accounts[0].Id);
            Assert.Equal("Facebook", accounts[0].Name);
            Assert.Equal("mark", accounts[0].Username);
            Assert.Equal("zuckerberg", accounts[0].Password);
            Assert.Equal("https://www.facebook.com", accounts[0].Url);
            Assert.Equal("Yo, bitches!", accounts[0].Note);
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
            Exceptions.AssertThrowsUnsupportedFeature(() => Client.DataCenterToTld("zx"),
                                                      "Unsupported data center");
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

            Exceptions.AssertThrowsInternalError(() => Client.RequestToken(flow),
                                                 "cookie is not set by the server");
        }

        [Fact]
        public void RequestUserInfo_makes_POST_request_and_returns_user_info()
        {
            var flow = new RestFlow()
                .Post(GetFixture("lookup-success-response"))
                    .ExpectUrl($"https://accounts.zoho.xyz/signin/v2/lookup/{Username}");

            var user = Client.RequestUserInfo(Username, OAuthCookieValue, "xyz", flow);

            Assert.Equal("633590133", user.Id);
            Assert.StartsWith("5edfa5597c0acd2b", user.Digest);
            Assert.Equal("com", user.Tld);
        }

        [Fact]
        public void RequestUserInfo_makes_POST_requests_and_returns_user_info_from_another_DC()
        {
            var flow = new RestFlow()
                .Post(GetFixture("lookup-another-dc-response"))
                    .ExpectUrl($"https://accounts.zoho.eu/signin/v2/lookup/{Username}")
                .Post(GetFixture("lookup-success-response"))
                    .ExpectUrl($"https://accounts.zoho.com/signin/v2/lookup/{Username}");

            var user = Client.RequestUserInfo(Username, OAuthCookieValue, "eu", flow);

            Assert.Equal("633590133", user.Id);
            Assert.StartsWith("5edfa5597c0acd2b", user.Digest);
            Assert.Equal("com", user.Tld);
        }

        [Fact]
        public void RequestUserInfo_throws_on_unknown_user()
        {
            var flow = new RestFlow()
                .Post(GetFixture("lookup-no-user-response"));

            Exceptions.AssertThrowsBadCredentials(
                () => Client.RequestUserInfo("unknown", OAuthCookieValue, "com", flow),
                "The username is invalid");
        }

        [Fact]
        public void RequestUserInfo_throws_on_unknown_error()
        {
            var flow = new RestFlow()
                .Post(GetFixture("lookup-unknown-error-response"));

            Exceptions.AssertThrowsInternalError(() => Client.RequestUserInfo(Username, OAuthCookieValue, "com", flow),
                                                 "Unexpected response: message: 'Unknown error', status code: '600/");
        }

        [Fact]
        public void LogIn_makes_POST_request_and_returns_server_cookies()
        {
            var flow = new RestFlow()
                .Post(GetFixture("login-success-response"), cookies: LoginCookies)
                    .ExpectUrl($"https://accounts.zoho.com/signin/v2/primary/{UserInfo.Id}/password")
                    .ExpectContent($"{{\"passwordauth\":{{\"password\":\"{Password}\"}}}}")
                    .ExpectCookie("iamcsr", OAuthCookieValue);

            var cookies = Client.LogIn(UserInfo, Password, OAuthCookieValue, null, GetSecureStorage(), flow);

            Assert.Equal(LoginCookieValue, cookies[LoginCookieName]);
        }

        [Fact]
        public void LogIn_makes_requests_to_specified_tld()
        {
            var flow = new RestFlow()
                .Post(GetFixture("login-success-response"), cookies: LoginCookies)
                    .ExpectUrl("https://accounts.zoho.eu/signin/");

            Client.LogIn(new Client.UserInfo("id", "digest", "eu"),
                         Password,
                         OAuthCookieValue,
                         null, GetSecureStorage(), flow);
        }

        [Fact]
        public void LogIn_throws_in_incorrect_password()
        {
            var flow = new RestFlow()
                .Post(GetFixture("login-incorrect-password-response"));

            Exceptions.AssertThrowsBadCredentials(
                () => Client.LogIn(UserInfo, Password, OAuthCookieValue, null, GetSecureStorage(), flow),
                "The password is incorrect");
        }

        [Fact]
        public void LogIn_continues_to_MFA_step()
        {
            var flow = new RestFlow()
                .Post(GetFixture("login-mfa-required-response"));

            Exceptions.AssertThrowsCanceledMultiFactor(() => Client.LogIn(UserInfo,
                                                                          Password,
                                                                          OAuthCookieValue,
                                                                          new CancellingUi(),
                                                                          GetSecureStorage(),
                                                                          flow),
                                                       "is canceled by the user");
        }

        [Fact]
        public void LogIn_throws_on_unknown_error()
        {
            var flow = new RestFlow()
                .Post(GetFixture("login-unknown-error-response"));

            Exceptions.AssertThrowsInternalError(
                () => Client.LogIn(UserInfo, Password, OAuthCookieValue, null, GetSecureStorage(), flow),
                "Unexpected response: message: 'Unknown error', status code: '600/");
        }

        [Fact(Skip = "MFA is not implemented yet")]
        public void LogIn_sends_remember_me_token_in_cookies()
        {
            var flow = new RestFlow()
                .Post("showsuccess('blah',)")
                    .ExpectCookie(RememberMeCookieName, RememberMeCookieValue);

            Client.LogIn(UserInfo, Password, OAuthCookieValue, null, GetSecureStorage(), flow);
        }

        [Fact(Skip = "MFA is not implemented yet")]
        public void LogIn_works_when_remember_me_token_is_not_available()
        {
            var flow = new RestFlow()
                .Post("showsuccess('blah',)");

            Client.LogIn(UserInfo, Password, OAuthCookieValue, null, GetEmptySecureStorage(), flow);
        }

        [Fact]
        public void LogIn_submits_otp_and_trust_and_returns_cookies()
        {
            var flow = new RestFlow()
                .Post(GetFixture("login-mfa-required-response"))
                .Post(GetFixture("mfa-success-response"))
                    .ExpectContent("{\"code\":\"1337\"}")
                .Post(GetFixture("trust-success-response"), cookies: LoginCookies)
                    .ExpectContent("{\"trust\":true}");
;
            var cookies = Client.LogIn(UserInfo,
                                       Password,
                                       OAuthCookieValue,
                                       new OtpProvidingUi(),
                                       GetSecureStorage(),
                                       flow);

            Assert.Equal(LoginCookieValue, cookies[LoginCookieName]);
        }

        [Fact]
        public void LogOut_makes_request_with_token_to_specific_url()
        {
            var flow = new RestFlow()
                .Get("RESULT=TRUE")
                    .ExpectUrl("https://accounts.zoho.com/logout?")
                    .ExpectCookie(LoginCookieName, LoginCookieValue);

            Client.LogOut(LoginCookies, "com", flow);
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

        [Theory]
        [InlineData("{'SECRETID':'id'}")]
        [InlineData("{'SECRETID':'id','SECRETDATA':'{}'}")]
        [InlineData("{'SECRETID':'id','SECRETDATA':'{\\'username\\':null,\\'password\\':null}'}")]
        [InlineData("{'SECRETID':'id','SECRETDATA':'{\\'username\\':\\'\\',\\'password\\':\\'\\'}'}")]
        [InlineData("{'SECRETID':'id','SECRETNAME':null,'SECRETURL':null,'SECURENOTE':null,'SECRETDATA':null,'ISSHARED':null}")]
        [InlineData("{'SECRETID':'id','SECRETNAME':'','SECRETURL':'','SECURENOTE':'','ISSHARED':''}")]
        public void ParseAccount_handles_missing_nulls_and_blanks(string json)
        {
            var secret = JsonConvert.DeserializeObject<R.Secret>(json);
            var account = Client.ParseAccount(secret, new byte[32]);

            Assert.Equal("id", account.Id);
            Assert.Equal("", account.Name);
            Assert.Equal("", account.Username);
            Assert.Equal("", account.Password);
            Assert.Equal("", account.Url);
            Assert.Equal("", account.Note);
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

        //
        // Helpers
        //

        private static Mock<ISecureStorage> GetSecureStorageMock()
        {
            var mock = new Mock<ISecureStorage>();
            mock.Setup(x => x.LoadString("remember-me-token-key")).Returns(RememberMeCookieName);
            mock.Setup(x => x.LoadString("remember-me-token-value")).Returns(RememberMeCookieValue);

            return mock;
        }

        private static ISecureStorage GetSecureStorage()
        {
            return GetSecureStorageMock().Object;
        }

        private static ISecureStorage GetEmptySecureStorage()
        {
            var mock = new Mock<ISecureStorage>();
            mock.Setup(x => x.LoadString(It.IsAny<string>())).Returns((string)null);

            return mock.Object;
        }

        private class CancellingUi: IUi
        {
            public Passcode ProvideGoogleAuthPasscode()
            {
                return Passcode.Cancel;
            }
        }

        private class OtpProvidingUi: IUi
        {
            public Passcode ProvideGoogleAuthPasscode()
            {
                return new Passcode("1337", true);
            }
        }

        //
        // Data
        //

        private const string Username = "dude@lebowski.com";
        private const string Password = "logjammin";

        // TODO: Rename to CSR
        private const string OAuthCookieName = "iamcsr";
        private const string OAuthCookieValue = "iamcsr-blah";

        private const string LoginCookieName = "login-cookie";
        private const string LoginCookieValue = "login-keks";

        private const string RememberMeCookieName = "remember-me-cookie-name";
        private const string RememberMeCookieValue = "remember-me-cookie-value";

        private Client.UserInfo UserInfo => new Client.UserInfo("id", "digest", "com");

        private static readonly Dictionary<string, string> OAuthCookies =
            new Dictionary<string, string> { { OAuthCookieName, OAuthCookieValue } };

        private static readonly Dictionary<string, string> LoginCookies =
            new Dictionary<string, string> { { LoginCookieName, LoginCookieValue } };
    }
}
