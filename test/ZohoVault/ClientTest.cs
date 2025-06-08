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
        //
        // Client.Open
        //

        [Fact]
        public void Open_returns_accounts()
        {
            // Act
            var vault = Client.Open(new Credentials(Username, Password, TestData.Passphrase), new Settings(), null, GetStorage(), MakeFullFlow());

            // Assert
            var accounts = vault.Accounts;
            accounts.Length.ShouldBe(2);

            accounts[0].Id.ShouldBe("30024000000008008");
            accounts[0].Name.ShouldBe("facebook");
            accounts[0].Username.ShouldBe("mark");
            accounts[0].Password.ShouldBe("zuckerberg");
            accounts[0].Url.ShouldBe("http://facebook.com");
            accounts[0].Note.ShouldBe("");

            accounts[1].Id.ShouldBe("30024000000008013");
            accounts[1].Name.ShouldBe("microsoft");
            accounts[1].Username.ShouldBe("bill");
            accounts[1].Password.ShouldBe("gates");
            accounts[1].Url.ShouldBe("http://microsoft.com");
            accounts[1].Note.ShouldBe("");
        }

        [Fact]
        public void Open_saves_cookies_when_keep_session_is_enabled()
        {
            // Arrange
            var storage = GetStorage();

            // Act
            Client.Open(new Credentials(Username, Password, TestData.Passphrase), new Settings { KeepSession = true }, null, storage, MakeFullFlow());

            // Assert
            storage.Values["cookies"].ShouldNotBeEmpty();
        }

        [Fact]
        public void Open_does_not_save_cookies_when_keep_session_is_disabled()
        {
            // Arrange
            var storage = GetStorage();

            // Act
            Client.Open(
                new Credentials(Username, Password, TestData.Passphrase),
                new Settings { KeepSession = false },
                null,
                storage,
                MakeFullFlow()
            );

            // Assert
            storage.Values.ShouldNotContainKey("cookies");
        }

        [Fact]
        public void Open_returns_shared_accounts()
        {
            // Arrange
            var flow = new RestFlow()
                .Get("", cookies: OAuthCookies)
                .Post(GetFixture("lookup-success-response"))
                .Post(GetFixture("login-success-response"), cookies: LoginCookies)
                .Get(GetFixture("auth-info-with-shared-items-response"))
                .Get(GetFixture("vault-with-shared-items-response"))
                .ExpectUrl($"https://vault.{DefaultDomain}/api/json/login?OPERATION_NAME=OPEN_VAULT&limit=-1")
                .Get(""); // Logout

            // Act
            var vault = Client.Open(new Credentials(Username, Password, TestData.Passphrase), new Settings(), null, GetStorage(), flow);

            // Assert
            var accounts = vault.Accounts;
            accounts.ShouldHaveSingleItem();

            accounts[0].Id.ShouldBe("113381000000009016");
            accounts[0].Name.ShouldBe("Facebook");
            accounts[0].Username.ShouldBe("mark");
            accounts[0].Password.ShouldBe("zuckerberg");
            accounts[0].Url.ShouldBe("https://www.facebook.com");
            accounts[0].Note.ShouldBe("Yo, bitches!");
        }

        //
        // Client.GetItem
        //

        [Fact]
        public void GetItem_makes_GET_request_and_returns_non_shared_account()
        {
            // Arrange
            const string id = "30024000000018381";
            var flow = new RestFlow()
                .Get(GetFixture("get-single-not-shared-item"))
                .ExpectUrl($"https://vault.{DefaultDomain}/api/rest/json/v1/secrets/{id}");
            var session = new Session(LoginCookies, DefaultDomain, flow, null, new Settings(), GetStorage(), TestData.Key);

            // Act
            var account = Client.GetItem(id, session);

            // Assert
            account.Id.ShouldBe(id);
            account.Name.ShouldBe("Abbott, Hamill and Upton");
            account.Username.ShouldBe("Duncan.Reinger");
            account.Password.ShouldBe("vqnjBS5KKHesQsb");
            account.Url.ShouldBe("http://jerome.info");
            account.Note.ShouldBe("engineer enterprise functionalities");

            session.SharingKey.ShouldBeNull();
        }

        [Fact]
        public void GetItem_makes_GET_request_downloads_profile_and_returns_shared_account()
        {
            // Arrange
            const string id = "34896000000013019";
            var flow = new RestFlow()
                // Item #1
                .Get(GetFixture("get-single-shared-item"))
                .ExpectUrl($"https://vault.{DefaultDomain}/api/rest/json/v1/secrets/{id}")
                .ExpectCookie(LoginCookieName, LoginCookieValue)
                // Sharing key
                .Get(GetFixture("vault-with-sharing-key-response"))
                .ExpectUrl($"https://vault.{DefaultDomain}/api/json/login?OPERATION_NAME=OPEN_VAULT&limit=0");
            var session = new Session(LoginCookies, DefaultDomain, flow, null, new Settings(), GetStorage(), TestData.Key3);

            // Act
            var account = Client.GetItem(id, session);

            // Assert
            account.Id.ShouldBe(id);
            account.Name.ShouldBe("blah.com");
            account.Username.ShouldBe("blah");
            account.Password.ShouldBe("pass");
            account.Url.ShouldBe("");
            account.Note.ShouldBe("blahahaha");

            session.SharingKey.ShouldNotBeNull();
        }

        [Fact]
        public void GetItem_makes_fetches_sharing_key_only_once()
        {
            // Arrange
            const string id = "34896000000013019";
            var flow1 = new RestFlow()
                // Item #1
                .Get(GetFixture("get-single-shared-item"))
                .ExpectUrl($"https://vault.{DefaultDomain}/api/rest/json/v1/secrets/{id}")
                .ExpectCookie(LoginCookieName, LoginCookieValue)
                // Sharing key
                .Get(GetFixture("vault-with-sharing-key-response"))
                .ExpectUrl($"https://vault.{DefaultDomain}/api/json/login?OPERATION_NAME=OPEN_VAULT&limit=0")
                // Item #2
                .Get(GetFixture("get-single-shared-item"))
                .ExpectUrl($"https://vault.{DefaultDomain}/api/rest/json/v1/secrets/{id}")
                // Item #3
                .Get(GetFixture("get-single-shared-item"))
                .ExpectUrl($"https://vault.{DefaultDomain}/api/rest/json/v1/secrets/{id}");
            var session = new Session(LoginCookies, DefaultDomain, flow1, null, new Settings(), GetStorage(), TestData.Key3);

            // Act
            for (var i = 0; i < 3; i++)
                Client.GetItem(id, session);

            // Assert
            session.SharingKey.ShouldNotBeNull();
        }

        //
        // Internal methods
        //

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
            // Act
            var domain = Client.UrlToDomain(url);

            // Assert
            domain.ShouldBe(expected);
        }

        [Theory]
        [InlineData("https://invalid.zoho.com/login")]
        [InlineData("https://zoho.com/login")]
        [InlineData("invalid")]
        [InlineData("http:/accounts.zoho.com/login")]
        public void UrlToDomain_throws_on_invalid_domain(string url)
        {
            // Act/Assert
            Exceptions.AssertThrowsInternalError(
                () => Client.UrlToDomain(url),
                $"Expected a valid URL with a domain starting with 'accounts.', got '{url}'"
            );
        }

        [Fact]
        public void RequestToken_makes_GET_request_and_returns_token()
        {
            // Arrange
            var flow = new RestFlow().Get("", cookies: OAuthCookies).ExpectUrl("https://accounts.zoho.com/oauth/v2/auth?");

            // Act
            var token = Client.RequestToken(flow);

            // Assert
            token.ShouldBe(CsrCookieValue);
        }

        [Fact]
        public void RequestToken_throws_on_missing_cookie()
        {
            // Arrange
            var flow = new RestFlow().Get("");

            // Act/Assert
            Exceptions.AssertThrowsInternalError(() => Client.RequestToken(flow), "cookie is not set by the server");
        }

        [Fact]
        public void RequestUserInfo_makes_POST_request_and_returns_user_info()
        {
            // Arrange
            var flow = new RestFlow().Post(GetFixture("lookup-success-response")).ExpectUrl($"https://accounts.zoho.xyz/signin/v2/lookup/{Username}");

            // Act
            var user = Client.RequestUserInfo(Username, CsrCookieValue, "zoho.xyz", flow);

            // Assert
            user.Id.ShouldBe("633590133");
            user.Digest.ShouldStartWith("5edfa5597c0acd2b");
            user.Domain.ShouldBe("zoho.com");
        }

        [Fact]
        public void RequestUserInfo_makes_POST_requests_and_returns_user_info_from_another_region()
        {
            // Arrange
            var flow = new RestFlow()
                .Post(GetFixture("lookup-another-region-response"))
                .ExpectUrl($"https://accounts.zoho.eu/signin/v2/lookup/{Username}")
                .Post(GetFixture("lookup-success-response"))
                .ExpectUrl($"https://accounts.zoho.com/signin/v2/lookup/{Username}");

            // Act
            var user = Client.RequestUserInfo(Username, CsrCookieValue, "zoho.eu", flow);

            // Assert
            user.Id.ShouldBe("633590133");
            user.Digest.ShouldStartWith("5edfa5597c0acd2b");
            user.Domain.ShouldBe("zoho.com");
        }

        [Fact]
        public void RequestUserInfo_throws_on_unknown_user()
        {
            // Arrange
            var flow = new RestFlow().Post(GetFixture("lookup-no-user-response"));

            // Act/Assert
            Exceptions.AssertThrowsBadCredentials(
                () => Client.RequestUserInfo("unknown", CsrCookieValue, DefaultDomain, flow),
                "The username is invalid"
            );
        }

        [Fact]
        public void RequestUserInfo_throws_on_unknown_error()
        {
            // Arrange
            var flow = new RestFlow().Post(GetFixture("lookup-unknown-error-response"));

            // Act/Assert
            Exceptions.AssertThrowsInternalError(
                () => Client.RequestUserInfo(Username, CsrCookieValue, DefaultDomain, flow),
                "Unexpected response: message: 'Unknown error', status code: '600/"
            );
        }

        [Fact]
        public void LogIn_makes_POST_request_and_returns_server_cookies()
        {
            // Arrange
            var flow = new RestFlow()
                .Post(GetFixture("login-success-response"), cookies: LoginCookies)
                .ExpectUrl($"https://accounts.zoho.com/signin/v2/primary/{UserInfo.Id}/password")
                .ExpectContent($"{{\"passwordauth\":{{\"password\":\"{Password}\"}}}}")
                .ExpectCookie("iamcsr", CsrCookieValue);

            // Act
            var cookies = Client.LogIn(UserInfo, Password, CsrCookieValue, null, GetStorage(), flow);

            // Assert
            cookies[LoginCookieName].ShouldBe(LoginCookieValue);
        }

        [Fact]
        public void LogIn_makes_requests_to_specified_regional_domain()
        {
            // Arrange
            var flow = new RestFlow().Post(GetFixture("login-success-response"), cookies: LoginCookies).ExpectUrl("https://accounts.zoho.eu/signin/");

            // Act
            Client.LogIn(new Client.UserInfo("id", "digest", "zoho.eu"), Password, CsrCookieValue, null, GetStorage(), flow);
        }

        [Fact]
        public void LogIn_throws_in_incorrect_password()
        {
            // Arrange
            var flow = new RestFlow().Post(GetFixture("login-incorrect-password-response"));

            // Act/Assert
            Exceptions.AssertThrowsBadCredentials(
                () => Client.LogIn(UserInfo, Password, CsrCookieValue, null, GetStorage(), flow),
                "The password is incorrect"
            );
        }

        [Fact]
        public void LogIn_continues_to_MFA_step()
        {
            // Arrange
            var flow = new RestFlow().Post(GetFixture("login-mfa-required-response"));

            // Act/Assert
            Exceptions.AssertThrowsCanceledMultiFactor(
                () => Client.LogIn(UserInfo, Password, CsrCookieValue, new CancellingUi(), GetStorage(), flow),
                "is canceled by the user"
            );
        }

        [Fact]
        public void LogIn_throws_on_unknown_error()
        {
            // Arrange
            var flow = new RestFlow().Post(GetFixture("login-unknown-error-response"));

            // Act/Assert
            Exceptions.AssertThrowsInternalError(
                () => Client.LogIn(UserInfo, Password, CsrCookieValue, null, GetStorage(), flow),
                "Unexpected response: message: 'Unknown error', status code: '600/"
            );
        }

        [Fact]
        public void LogIn_sends_remember_me_token_in_cookies()
        {
            // Arrange
            var flow = new RestFlow()
                .Post(GetFixture("login-success-response"), cookies: LoginCookies)
                .ExpectCookie(RememberMeCookieName, RememberMeCookieValue);

            // Act
            Client.LogIn(UserInfo, Password, CsrCookieValue, null, GetStorage(), flow);
        }

        [Fact]
        public void LogIn_works_when_remember_me_token_is_not_available()
        {
            // Arrange
            var flow = new RestFlow()
                .Post(GetFixture("login-mfa-required-response"))
                .Post(GetFixture("mfa-success-response"))
                .Post(GetFixture("trust-success-response"));

            // Act
            Client.LogIn(UserInfo, Password, CsrCookieValue, new OtpProvidingUi(), GetEmptyStorage(), flow);
        }

        [Fact]
        public void LogIn_submits_otp_and_trust_and_returns_cookies()
        {
            // Arrange
            var flow = new RestFlow()
                .Post(GetFixture("login-mfa-required-response"))
                .Post(GetFixture("mfa-success-response"))
                .ExpectContent("{\"code\":\"1337\"}")
                .Post(GetFixture("trust-success-response"), cookies: LoginCookies)
                .ExpectContent("{\"trust\":true}");

            // Act
            var cookies = Client.LogIn(UserInfo, Password, CsrCookieValue, new OtpProvidingUi(), GetStorage(), flow);

            // Assert
            cookies[LoginCookieName].ShouldBe(LoginCookieValue);
        }

        [Fact]
        public void LogOut_makes_request_with_token_to_specific_url()
        {
            // Arrange
            var flow = new RestFlow()
                .Get("RESULT=TRUE")
                .ExpectUrl("https://accounts.zoho.com/logout?")
                .ExpectCookie(LoginCookieName, LoginCookieValue);

            // Act
            Client.LogOut(LoginCookies, DefaultDomain, flow);
        }

        [Fact]
        public void LogOut_accepts_302_HTTP_status_code()
        {
            // Arrange
            var flow = new RestFlow().Get("", HttpStatusCode.Redirect);

            // Act
            Client.LogOut(LoginCookies, DefaultDomain, flow);
        }

        [Fact]
        public void RequestAuthInfo_makes_GET_request_to_specific_url_and_returns_auth_info()
        {
            // Arrange
            var flow = new RestFlow()
                .Get(GetFixture("auth-info-response"))
                .ExpectUrl("https://vault.zoho.com/api/json/login?OPERATION_NAME=GET_LOGIN")
                .ExpectCookie(LoginCookieName, LoginCookieValue);

            // Act
            var info = Client.RequestAuthInfo(LoginCookies, DefaultDomain, flow);

            // Assert
            info.IterationCount.ShouldBe(1000);
            info.Salt.ShouldBe("f78e6ffce8e57501a02c9be303db2c68".ToBytes());
            info.EncryptionCheck.ShouldBe("awNZM8agxVecKpRoC821Oq6NlvVwm6KpPGW+cLdzRoc2Mg5vqPQzoONwww==".Decode64());
        }

        [Fact]
        public void RequestAuthInfo_throws_on_unknown_kdf_method()
        {
            // Arrange
            var flow = new RestFlow()
                .Get(GetFixture("auth-info-with-unknown-kdf-response"))
                .ExpectUrl("https://vault.zoho.com/api/json/login?OPERATION_NAME=GET_LOGIN")
                .ExpectCookie(LoginCookieName, LoginCookieValue);

            // Act/Assert
            Exceptions.AssertThrowsUnsupportedFeature(
                () => Client.RequestAuthInfo(LoginCookies, DefaultDomain, flow),
                "KDF method 'UNKNOWN_KDF' is not supported"
            );
        }

        [Fact]
        public void FetchVault_makes_GET_request_to_specific_url_and_returns_vault_records()
        {
            // Arrange
            var flow = new RestFlow()
                .Get(GetFixture("vault-response"))
                .ExpectUrl($"https://vault.{DefaultDomain}/api/json/login?OPERATION_NAME=OPEN_VAULT&limit=-1");

            // Act
            var vault = Client.FetchVault(LoginCookies, DefaultDomain, flow);

            // Assert
            vault.Secrets.ShouldNotBeEmpty();
        }

        [Fact]
        public void FetchSecret_makes_GET_request_to_specific_url_and_returns_secret()
        {
            // Arrange
            const string id = "34896000000013019";
            var flow = new RestFlow()
                .Get(GetFixture("get-single-shared-item"))
                .ExpectUrl($"https://vault.{DefaultDomain}/api/rest/json/v1/secrets/{id}");

            // Act
            var secret = Client.FetchSecret(LoginCookies, DefaultDomain, id, flow);

            // Assert
            secret.Id.ShouldBe(id);
            secret.Name.ShouldBe("blah.com");
            secret.IsShared.ShouldBe("YES");
        }

        [Fact]
        public void DeriveAndVerifyVaultKey_returns_key()
        {
            // Act
            var key = Client.DeriveAndVerifyVaultKey(TestData.Passphrase, TestData.AuthInfo);

            // Assert
            key.ShouldBe(TestData.Key);
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

            Client.DecryptSharingKey(vault, TestData.Key).ShouldBeNull();
        }

        [Fact]
        public void DecryptSharingKey_returns_key()
        {
            var vault = ParseFixture<R.ResponseEnvelope<R.Vault>>("vault-with-shared-items-response").Payload;

            var sharingKey = Client.DecryptSharingKey(vault, TestData.Key2).ToUtf8();

            sharingKey.ShouldBe("ItaDMKNE|x4gu1gEom9f@'GWsjH!}$OS");
        }

        [Theory]
        [InlineData("""{"SECRETID": "id"}""")]
        [InlineData("""{"SECRETID": "id", "SECRETDATA": "{}"}""")]
        [InlineData("""{"SECRETID": "id", "SECRETDATA": "{\"username\":null,\"password\":null}"}""")]
        [InlineData("""{"SECRETID": "id", "SECRETDATA": "{\"username\":\"\",\"password\":\"\"}"}""")]
        [InlineData("""{"SECRETID": "id", "SECRETNAME": null, "SECRETURL": null, "SECURENOTE": null, "SECRETDATA": null, "ISSHARED": null}""")]
        [InlineData("""{"SECRETID": "id", "SECRETNAME": "", "SECRETURL": "", "SECURENOTE": "","ISSHARED": ""}""")]
        public void ParseAccount_handles_missing_nulls_and_blanks_in_R_Secret(string json)
        {
            var secret = JsonConvert.DeserializeObject<R.Secret>(json);
            var account = Client.ParseAccount(Client.ConvertToSecret(secret), new byte[32]);

            account.Id.ShouldBe("id");
            account.Name.ShouldBe("");
            account.Username.ShouldBe("");
            account.Password.ShouldBe("");
            account.Url.ShouldBe("");
            account.Note.ShouldBe("");
        }

        [Theory]
        [InlineData("""{"secretid": "id", "secretData": "{}"}""")]
        [InlineData("""{"secretid": "id", "secretData": "{\"username\":null,\"password\":null}"}""")]
        [InlineData("""{"secretid": "id", "secretData": "{\"username\":\"\",\"password\":\"\"}"}""")]
        [InlineData("""{"secretid": "id", "secretname": null, "secreturl": null, "notes": null, "secretData": "{}", "isshared": null}""")]
        [InlineData("""{"secretid": "id", "secretname": "", "secreturl": "", "notes": "", "secretData": "{}", "isshared": ""}""")]
        public void ParseAccount_handles_missing_nulls_and_blanks_in_R_SingleSecret(string json)
        {
            var singleSecret = JsonConvert.DeserializeObject<R.SingleSecret>(json);
            var account = Client.ParseAccount(Client.ConvertToSecret(singleSecret), new byte[32]);

            account.Id.ShouldBe("id");
            account.Name.ShouldBe("");
            account.Username.ShouldBe("");
            account.Password.ShouldBe("");
            account.Url.ShouldBe("");
            account.Note.ShouldBe("");
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
                storage.Values.ShouldContainKey("remember-me-token-key");
                storage.Values["remember-me-token-key"].ShouldBe(name);

                storage.Values.ShouldContainKey("remember-me-token-value");
                storage.Values["remember-me-token-value"].ShouldBe(value);
            }
            else
            {
                storage.Values.ShouldBeEmpty();
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
                .ExpectUrl($"https://vault.{DefaultDomain}/api/json/login?OPERATION_NAME=OPEN_VAULT&limit=-1")
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

        private static Client.UserInfo UserInfo => new("id", "digest", DefaultDomain);

        private static readonly Dictionary<string, string> OAuthCookies = new() { [CsrCookieName] = CsrCookieValue };
        private static readonly Dictionary<string, string> LoginCookies = new() { [LoginCookieName] = LoginCookieValue };
    }
}
