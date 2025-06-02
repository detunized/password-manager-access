// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Net;
using Newtonsoft.Json;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.ZohoVault;
using PasswordManagerAccess.ZohoVault.Ui;
using Shouldly;
using Xunit;
using R = PasswordManagerAccess.ZohoVault.Response;

namespace PasswordManagerAccess.Test.ZohoVault
{
    // TODO: Add more MFA tests
    public class ClientTest : TestBase
    {
        [Fact]
        public void OpenVault_returns_accounts()
        {
            var accounts = Client.OpenVault(
                new Credentials(Username, Password, TestData.Passphrase),
                new Settings(),
                null,
                GetStorage(),
                MakeFullFlow()
            );

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
        public void OpenVault_saves_cookies_when_keep_session_is_enabled()
        {
            var storage = GetStorage();
            Client.OpenVault(
                new Credentials(Username, Password, TestData.Passphrase),
                new Settings { KeepSession = true },
                null,
                storage,
                MakeFullFlow()
            );

            storage.Values["cookies"].ShouldNotBeEmpty();
        }

        [Fact]
        public void OpenVault_doe_not_save_cookies_when_keep_session_is_disabled()
        {
            var storage = GetStorage();
            Client.OpenVault(
                new Credentials(Username, Password, TestData.Passphrase),
                new Settings { KeepSession = false },
                null,
                storage,
                MakeFullFlow()
            );

            storage.Values.ShouldNotContainKey("cookies");
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

            var vault = Vault.Open(new Credentials(Username, Password, TestData.Passphrase), new Settings(), null, GetStorage(), flow);
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
        [InlineData("https://accounts.zoho.com/singin", "zoho.com")]
        [InlineData("https://accounts.zohocloud.ca/singin", "zohocloud.ca")]
        [InlineData("https://accounts.zoho.eu/singin", "zoho.eu")]
        [InlineData("https://accounts.zoho.in/singin", "zoho.in")]
        [InlineData("https://accounts.zoho.jp/singin", "zoho.jp")]
        [InlineData("https://accounts.zoho.uk/singin", "zoho.uk")]
        [InlineData("https://accounts.zoho.com.au/singin", "zoho.com.au")]
        public void UrlToDomain_extracts_base_domain_from_url(string url, string expected)
        {
            var domain = Client.UrlToDomain(url);
            Assert.Equal(expected, domain);
        }

        [Theory]
        [InlineData("https://invalid.zoho.com/login")]
        [InlineData("https://zoho.com/login")]
        [InlineData("invalid")]
        [InlineData("http:/accounts.zoho.com/login")]
        public void UrlToDomain_throws_on_invalid_domain(string url)
        {
            Exceptions.AssertThrowsInternalError(
                () => Client.UrlToDomain(url),
                $"Expected a valid URL with a domain starting with 'accounts.', got '{url}'"
            );
        }

        [Fact]
        public void RequestToken_makes_GET_request_and_returns_token()
        {
            var flow = new RestFlow().Get("", cookies: OAuthCookies).ExpectUrl("https://accounts.zoho.com/oauth/v2/auth?");

            var token = Client.RequestToken(flow);

            Assert.Equal(CsrCookieValue, token);
        }

        [Fact]
        public void RequestToken_throws_on_missing_cookie()
        {
            var flow = new RestFlow().Get("");

            Exceptions.AssertThrowsInternalError(() => Client.RequestToken(flow), "cookie is not set by the server");
        }

        [Fact]
        public void RequestUserInfo_makes_POST_request_and_returns_user_info()
        {
            var flow = new RestFlow().Post(GetFixture("lookup-success-response")).ExpectUrl($"https://accounts.zoho.xyz/signin/v2/lookup/{Username}");

            var user = Client.RequestUserInfo(Username, CsrCookieValue, "zoho.xyz", flow);

            Assert.Equal("633590133", user.Id);
            Assert.StartsWith("5edfa5597c0acd2b", user.Digest);
            Assert.Equal("zoho.com", user.Domain);
        }

        [Fact]
        public void RequestUserInfo_makes_POST_requests_and_returns_user_info_from_another_region()
        {
            var flow = new RestFlow()
                .Post(GetFixture("lookup-another-region-response"))
                .ExpectUrl($"https://accounts.zoho.eu/signin/v2/lookup/{Username}")
                .Post(GetFixture("lookup-success-response"))
                .ExpectUrl($"https://accounts.zoho.com/signin/v2/lookup/{Username}");

            var user = Client.RequestUserInfo(Username, CsrCookieValue, "zoho.eu", flow);

            Assert.Equal("633590133", user.Id);
            Assert.StartsWith("5edfa5597c0acd2b", user.Digest);
            Assert.Equal("zoho.com", user.Domain);
        }

        [Fact]
        public void RequestUserInfo_throws_on_unknown_user()
        {
            var flow = new RestFlow().Post(GetFixture("lookup-no-user-response"));

            Exceptions.AssertThrowsBadCredentials(
                () => Client.RequestUserInfo("unknown", CsrCookieValue, DefaultDomain, flow),
                "The username is invalid"
            );
        }

        [Fact]
        public void RequestUserInfo_throws_on_unknown_error()
        {
            var flow = new RestFlow().Post(GetFixture("lookup-unknown-error-response"));

            Exceptions.AssertThrowsInternalError(
                () => Client.RequestUserInfo(Username, CsrCookieValue, DefaultDomain, flow),
                "Unexpected response: message: 'Unknown error', status code: '600/"
            );
        }

        [Fact]
        public void LogIn_makes_POST_request_and_returns_server_cookies()
        {
            var flow = new RestFlow()
                .Post(GetFixture("login-success-response"), cookies: LoginCookies)
                .ExpectUrl($"https://accounts.zoho.com/signin/v2/primary/{UserInfo.Id}/password")
                .ExpectContent($"{{\"passwordauth\":{{\"password\":\"{Password}\"}}}}")
                .ExpectCookie("iamcsr", CsrCookieValue);

            var cookies = Client.LogIn(UserInfo, Password, CsrCookieValue, null, GetStorage(), flow);

            Assert.Equal(LoginCookieValue, cookies[LoginCookieName]);
        }

        [Fact]
        public void LogIn_makes_requests_to_specified_regional_domain()
        {
            var flow = new RestFlow().Post(GetFixture("login-success-response"), cookies: LoginCookies).ExpectUrl("https://accounts.zoho.eu/signin/");

            Client.LogIn(new Client.UserInfo("id", "digest", "zoho.eu"), Password, CsrCookieValue, null, GetStorage(), flow);
        }

        [Fact]
        public void LogIn_throws_in_incorrect_password()
        {
            var flow = new RestFlow().Post(GetFixture("login-incorrect-password-response"));

            Exceptions.AssertThrowsBadCredentials(
                () => Client.LogIn(UserInfo, Password, CsrCookieValue, null, GetStorage(), flow),
                "The password is incorrect"
            );
        }

        [Fact]
        public void LogIn_continues_to_MFA_step()
        {
            var flow = new RestFlow().Post(GetFixture("login-mfa-required-response"));

            Exceptions.AssertThrowsCanceledMultiFactor(
                () => Client.LogIn(UserInfo, Password, CsrCookieValue, new CancellingUi(), GetStorage(), flow),
                "is canceled by the user"
            );
        }

        [Fact]
        public void LogIn_throws_on_unknown_error()
        {
            var flow = new RestFlow().Post(GetFixture("login-unknown-error-response"));

            Exceptions.AssertThrowsInternalError(
                () => Client.LogIn(UserInfo, Password, CsrCookieValue, null, GetStorage(), flow),
                "Unexpected response: message: 'Unknown error', status code: '600/"
            );
        }

        [Fact]
        public void LogIn_sends_remember_me_token_in_cookies()
        {
            var flow = new RestFlow()
                .Post(GetFixture("login-success-response"), cookies: LoginCookies)
                .ExpectCookie(RememberMeCookieName, RememberMeCookieValue);

            Client.LogIn(UserInfo, Password, CsrCookieValue, null, GetStorage(), flow);
        }

        [Fact]
        public void LogIn_works_when_remember_me_token_is_not_available()
        {
            var flow = new RestFlow()
                .Post(GetFixture("login-mfa-required-response"))
                .Post(GetFixture("mfa-success-response"))
                .Post(GetFixture("trust-success-response"));

            Client.LogIn(UserInfo, Password, CsrCookieValue, new OtpProvidingUi(), GetEmptyStorage(), flow);
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
            var cookies = Client.LogIn(UserInfo, Password, CsrCookieValue, new OtpProvidingUi(), GetStorage(), flow);

            Assert.Equal(LoginCookieValue, cookies[LoginCookieName]);
        }

        [Fact]
        public void LogOut_makes_request_with_token_to_specific_url()
        {
            var flow = new RestFlow()
                .Get("RESULT=TRUE")
                .ExpectUrl("https://accounts.zoho.com/logout?")
                .ExpectCookie(LoginCookieName, LoginCookieValue);

            Client.LogOut(LoginCookies, DefaultDomain, flow);
        }

        [Fact]
        public void LogOut_accepts_302_HTTP_status_code()
        {
            var flow = new RestFlow().Get("", HttpStatusCode.Redirect);

            Client.LogOut(LoginCookies, DefaultDomain, flow);
        }

        [Fact]
        public void RequestAuthInfo_makes_GET_request_to_specific_url_and_returns_auth_info()
        {
            var flow = new RestFlow()
                .Get(GetFixture("auth-info-response"))
                .ExpectUrl("https://vault.zoho.com/api/json/login?OPERATION_NAME=GET_LOGIN")
                .ExpectCookie(LoginCookieName, LoginCookieValue);

            var info = Client.RequestAuthInfo(LoginCookies, DefaultDomain, flow);

            Assert.Equal(1000, info.IterationCount);
            Assert.Equal("f78e6ffce8e57501a02c9be303db2c68".ToBytes(), info.Salt);
            Assert.Equal("awNZM8agxVecKpRoC821Oq6NlvVwm6KpPGW+cLdzRoc2Mg5vqPQzoONwww==".Decode64(), info.EncryptionCheck);
        }

        [Fact]
        public void RequestAuthInfo_throws_on_unknown_kdf_method()
        {
            var flow = new RestFlow()
                .Get(GetFixture("auth-info-with-unknown-kdf-response"))
                .ExpectUrl("https://vault.zoho.com/api/json/login?OPERATION_NAME=GET_LOGIN")
                .ExpectCookie(LoginCookieName, LoginCookieValue);

            Exceptions.AssertThrowsUnsupportedFeature(
                () => Client.RequestAuthInfo(LoginCookies, DefaultDomain, flow),
                "KDF method 'UNKNOWN_KDF' is not supported"
            );
        }

        [Fact]
        public void DownloadVault_makes_GET_request_to_specific_url_and_returns_vault_records()
        {
            var flow = new RestFlow().Get(GetFixture("vault-response")).ExpectUrl("https://vault.zoho.com/api/json/login?OPERATION_NAME=OPEN_VAULT");

            var vault = Client.DownloadVault(LoginCookies, DefaultDomain, flow);

            Assert.NotEmpty(vault.Secrets);
        }

        [Fact]
        public void DeriveAndVerifyVaultKey_returns_key()
        {
            var key = Client.DeriveAndVerifyVaultKey(TestData.Passphrase, TestData.AuthInfo);

            Assert.Equal(TestData.Key, key);
        }

        [Fact]
        public void Authenticate_throws_on_incorrect_passphrase()
        {
            Exceptions.AssertThrowsBadCredentials(
                () => Client.DeriveAndVerifyVaultKey("Not really a passphrase", TestData.AuthInfo),
                "Passphrase is incorrect"
            );
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

        [Theory]
        [InlineData("blah", "blah-blah-blah", false)]
        [InlineData("TFATICKET_63359013", "blah-blah-blah", false)]
        [InlineData("IAMTFATICKET_633590133", "blah-blah-blah", true)]
        [InlineData("IAMEU1TFATICKET_20085519105", "blah-blah-blah", true)]
        public void FindAndSaveRememberMeToken_stores_token(string name, string value, bool isValid)
        {
            var storage = GetEmptyStorage();
            Client.FindAndSaveRememberMeToken(
                new Dictionary<string, string>
                {
                    ["pff"] = "grr",
                    [name] = value,
                    ["grr"] = "pff",
                },
                storage
            );

            if (isValid)
            {
                var tokenKey = Assert.Contains("remember-me-token-key", storage.Values);
                Assert.Equal(name, tokenKey);

                var tokenValue = Assert.Contains("remember-me-token-value", storage.Values);
                Assert.Equal(value, tokenValue);
            }
            else
            {
                Assert.Empty(storage.Values);
            }
        }

        //
        // Helpers
        //

        private static MemoryStorage GetStorage()
        {
            return new MemoryStorage(
                new Dictionary<string, string>
                {
                    ["remember-me-token-key"] = RememberMeCookieName,
                    ["remember-me-token-value"] = RememberMeCookieValue,
                }
            );
        }

        private static MemoryStorage GetEmptyStorage()
        {
            return new MemoryStorage();
        }

        private class CancellingUi : IUi
        {
            public Passcode ProvideGoogleAuthPasscode()
            {
                return Passcode.Cancel;
            }
        }

        private class OtpProvidingUi : IUi
        {
            public Passcode ProvideGoogleAuthPasscode()
            {
                return new Passcode("1337", true);
            }
        }

        private RestFlow MakeFullFlow()
        {
            return new RestFlow()
                .Get("", cookies: OAuthCookies)
                .Post(GetFixture("lookup-success-response"))
                .Post(GetFixture("login-success-response"), cookies: LoginCookies)
                .Get(GetFixture("auth-info-response"))
                .Get(GetFixture("vault-response"))
                .Get(""); // Logout
        }

        //
        // Data
        //

        private const string Username = "dude@lebowski.com";
        private const string Password = "logjammin";

        private const string CsrCookieName = "iamcsr";
        private const string CsrCookieValue = "iamcsr-blah";

        private const string LoginCookieName = "login-cookie";
        private const string LoginCookieValue = "login-keks";

        private const string RememberMeCookieName = "remember-me-cookie-name";
        private const string RememberMeCookieValue = "remember-me-cookie-value";

        private const string DefaultDomain = "zoho.com";

        private Client.UserInfo UserInfo => new("id", "digest", DefaultDomain);

        private static readonly Dictionary<string, string> OAuthCookies = new() { { CsrCookieName, CsrCookieValue } };
        private static readonly Dictionary<string, string> LoginCookies = new() { { LoginCookieName, LoginCookieValue } };
    }
}
