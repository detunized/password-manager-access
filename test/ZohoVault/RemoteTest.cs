// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Specialized;
using System.Net;
using Moq;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.ZohoVault;
using Xunit;

namespace PasswordManagerAccess.Test.ZohoVault
{
    public class RemoteTest: TestBase
    {
        public const string Username = "lebowski";
        public const string Password = "logjammin";
        public const string Token = "1auth2token3";
        public const string LoginUrlPrefix = "https://accounts.zoho.com/login?";
        public const string LogoutUrlPrefix = "https://accounts.zoho.com/apiauthtoken/delete?";
        public const string LogoutResponse = "RESULT=TRUE";

        [Fact]
        public void Login_returns_token()
        {
            Assert.Equal(Token, Remote.Login(Username, Password, SetupWebClientWithSuccess().Object));
        }

        [Fact]
        public void Login_makes_post_request_to_specific_url()
        {
            var webClient = SetupWebClientWithSuccess();
            Remote.Login(Username, Password, webClient.Object);

            webClient.Verify(
                x => x.UploadValues(It.Is<string>(s => s.StartsWith(LoginUrlPrefix)), It.IsAny<NameValueCollection>()),
                Times.Once);
        }

        [Fact]
        public void Login_makes_post_request_with_correct_username_and_password()
        {
            var webClient = SetupWebClientWithSuccess();
            Remote.Login(Username, Password, webClient.Object);

            webClient.Verify(
                x => x.UploadValues(
                    It.IsAny<string>(),
                    It.Is<NameValueCollection>(p => p["LOGIN_ID"] == Username && p["PASSWORD"] == Password)),
                Times.Once);
        }

        [Fact]
        public void Login_makes_post_request_with_cookie_set()
        {
            var webClient = SetupWebClientWithSuccess();
            Remote.Login(Username, Password, webClient.Object);

            Assert.Contains("iamcsr=12345678", webClient.Object.Headers["Cookie"]);
        }

        [Fact]
        public void Login_throws_on_network_error()
        {
            var webClient = SetupWebClient(new WebException());
            Exceptions.AssertThrowsNetworkError(() => Remote.Login(Username, Password, webClient.Object),
                                                "Network error occurred");
        }

        [Fact]
        public void Login_throws_on_error()
        {
            var webClient = SetupWebClient("showerror('It failed')");
            Exceptions.AssertThrowsBadCredentials(() => Remote.Login(Username, Password, webClient.Object),
                                                  "Login failed, most likely the credentials are invalid");
        }

        [Fact]
        public void Logout_makes_get_request_to_specific_url()
        {
            var webClient = SetupWebClientForGet(LogoutResponse);
            Remote.Logout(Token, webClient.Object);

            webClient.Verify(
                x => x.DownloadData(It.Is<string>(s => s.StartsWith(LogoutUrlPrefix))),
                Times.Once);
        }

        [Fact]
        public void Logout_makes_get_request_with_token()
        {
            var webClient = SetupWebClientForGet(LogoutResponse);
            Remote.Logout(Token, webClient.Object);

            var authToken = string.Format("AUTHTOKEN={0}", Token);
            webClient.Verify(
                x => x.DownloadData(It.Is<string>(s => s.EndsWith(authToken))),
                Times.Once);
        }

        [Fact]
        public void Authenticate_returns_key()
        {
            var webClient = SetupWebClientForGetWithFixture("auth-info-response");
            Assert.Equal(TestData.Key, Remote.Authenticate(Token, TestData.Passphrase, webClient.Object));
        }

        [Fact]
        public void Authenticate_throws_on_incorrect_passphrase()
        {
            var webClient = SetupWebClientForGetWithFixture("auth-info-response");
            Exceptions.AssertThrowsBadCredentials(
                () => Remote.Authenticate(Token, "Not really a passphrase", webClient.Object),
                "Passphrase is incorrect");
        }

        [Fact]
        public void DownloadVault_returns_vault_json()
        {
            var webClient = SetupWebClientForGetWithFixture("vault-response");
            Assert.NotNull(Remote.DownloadVault(Token, TestData.Key, webClient.Object));
        }

        [Fact]
        public void DownloadVault_throws_on_network_error()
        {
            var webClient = SetupWebClientForGet(new WebException());
            Exceptions.AssertThrowsNetworkError(() => Remote.DownloadVault(Token, TestData.Key, webClient.Object),
                                                "Network error occurred");
        }

        // TODO: Add more GetAuthInfo tests

        [Fact]
        public void GetAuthInfo_returns_auth_info()
        {
            var webClient = SetupWebClientForGetWithFixture("auth-info-response");
            var info = Remote.GetAuthInfo(Token, webClient.Object);

            Assert.Equal(1000, info.IterationCount);
            Assert.Equal("f78e6ffce8e57501a02c9be303db2c68".ToBytes(), info.Salt);
            Assert.Equal("awNZM8agxVecKpRoC821Oq6NlvVwm6KpPGW+cLdzRoc2Mg5vqPQzoONwww==".Decode64(), info.EncryptionCheck);
        }

        //
        // Helpers
        //

        private static Mock<IWebClient> SetupWebClientWithSuccess()
        {
            return SetupWebClient("showsuccess('')");
        }

        private static Mock<IWebClient> SetupWebClient(string response)
        {
            var webClient = SetupWebClientHeaders();
            webClient
                .Setup(x => x.UploadValues(It.IsAny<string>(), It.IsAny<NameValueCollection>()))
                .Returns(response.ToBytes());

            return webClient;
        }

        private static Mock<IWebClient> SetupWebClient(Exception e)
        {
            var webClient = SetupWebClientHeaders();
            webClient
                .Setup(x => x.UploadValues(It.IsAny<string>(), It.IsAny<NameValueCollection>()))
                .Throws(e);

            return webClient;
        }

        private static Mock<IWebClient> SetupWebClientHeaders()
        {
            var responseHeaders = new WebHeaderCollection();
            responseHeaders[HttpResponseHeader.SetCookie] = string.Format("IAMAUTHTOKEN={0};", Token);

            var webClient = new Mock<IWebClient>();
            webClient
                .Setup(x => x.Headers)
                .Returns(new WebHeaderCollection());
            webClient
                .Setup(x => x.ResponseHeaders)
                .Returns(responseHeaders);

            return webClient;
        }

        private static Mock<IWebClient> SetupWebClientForGet(string response)
        {
            var webClient = new Mock<IWebClient>();
            webClient
                .Setup(x => x.Headers)
                .Returns(new WebHeaderCollection());
            webClient
                .Setup(x => x.DownloadData(It.IsAny<string>()))
                .Returns(response.ToBytes());

            return webClient;
        }

        private static Mock<IWebClient> SetupWebClientForGet(Exception e)
        {
            var webClient = new Mock<IWebClient>();
            webClient
                .Setup(x => x.Headers)
                .Returns(new WebHeaderCollection());
            webClient
                .Setup(x => x.DownloadData(It.IsAny<string>()))
                .Throws(e);

            return webClient;
        }

        private Mock<IWebClient> SetupWebClientForGetWithFixture(string filename)
        {
            return SetupWebClientForGet(GetFixture(filename));
        }
    }
}
