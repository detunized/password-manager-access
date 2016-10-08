// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Specialized;
using System.IO;
using System.Net;
using Moq;
using Newtonsoft.Json.Linq;
using NUnit.Framework;

namespace ZohoVault.Test
{
    [TestFixture]
    class RemoteTest
    {
        public const string Username = "lebowski";
        public const string Password = "logjammin";
        public const string Token = "1auth2token3";
        public const string LoginUrlPrefix = "https://accounts.zoho.com/login?";

        [Test]
        public void Login_returns_token()
        {
            Assert.That(
                Remote.Login(Username, Password, SetupWebClientWithSuccess().Object),
                Is.EqualTo(Token));
        }

        [Test]
        public void Login_makes_post_request_to_specific_url()
        {
            var webClient = SetupWebClientWithSuccess();
            Remote.Login(Username, Password, webClient.Object);

            webClient.Verify(
                x => x.UploadValues(It.Is<string>(s => s.StartsWith(LoginUrlPrefix)), It.IsAny<NameValueCollection>()),
                Times.Once);
        }

        [Test]
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

        [Test]
        public void Login_makes_post_request_with_cookie_set()
        {
            var webClient = SetupWebClientWithSuccess();
            Remote.Login(Username, Password, webClient.Object);

            Assert.That(webClient.Object.Headers["Cookie"], Is.StringContaining("iamcsr=12345678"));
        }

        [Test]
        public void Login_throws_on_network_error()
        {
            var webClient = SetupWebClient(new WebException());
            Assert.That(
                () => Remote.Login(Username, Password, webClient.Object),
                Throws
                    .TypeOf<FetchException>()
                    .And.Property("Reason").EqualTo(FetchException.FailureReason.NetworkError)
                    .And.Message.EqualTo("Network error occurred")
                    .And.InnerException.TypeOf<WebException>());
        }

        [Test]
        public void Login_throws_on_error()
        {
            Assert.That(
                () => Remote.Login(Username, Password, SetupWebClient("showerror('It failed')").Object),
                Throws.TypeOf<InvalidOperationException>());
        }

        [Test]
        public void Authenticate_returns_key()
        {
            var webClient = SetupWebClientForGetWithFixture("auth-info-response");
            Assert.That(
                Remote.Authenticate(Token, TestData.Passphrase, webClient.Object),
                Is.EqualTo(TestData.Key));
        }

        [Test]
        public void Authenticate_throws_on_incorrect_passphrase()
        {
            var webClient = SetupWebClientForGetWithFixture("auth-info-response");
            Assert.That(
                () => Remote.Authenticate(Token, "Not really a passphrase", webClient.Object),
                Throws.TypeOf<InvalidOperationException>());
        }

        [Test]
        public void DownloadVault_returns_vault_json()
        {
            var webClient = SetupWebClientForGetWithFixture("vault-response");
            Assert.That(
                Remote.DownloadVault(Token, TestData.Key, webClient.Object),
                Is.Not.Null);
        }

        [Test]
        public void DownloadVault_throws_on_network_error()
        {
            var webClient = SetupWebClientForGet(new WebException());
            Assert.That(
                () => Remote.DownloadVault(Token, TestData.Key, webClient.Object),
                Throws
                    .TypeOf<FetchException>()
                    .And.Property("Reason").EqualTo(FetchException.FailureReason.NetworkError)
                    .And.Message.EqualTo("Network error occurred")
                    .And.InnerException.TypeOf<WebException>());
        }

        // TODO: Add more GetAuthInfo tests

        [Test]
        public void GetAuthInfo_returns_auth_info()
        {
            var webClient = SetupWebClientForGetWithFixture("auth-info-response");
            var info = Remote.GetAuthInfo(Token, webClient.Object);

            Assert.That(
                info.IterationCount,
                Is.EqualTo(1000));
            Assert.That(
                info.Salt,
                Is.EqualTo("f78e6ffce8e57501a02c9be303db2c68".ToBytes()));
            Assert.That(
                info.EncryptionCheck,
                Is.EqualTo("awNZM8agxVecKpRoC821Oq6NlvVwm6KpPGW+cLdzRoc2Mg5vqPQzoONwww==".Decode64()));
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

        private static Mock<IWebClient> SetupWebClientForGetWithFixture(string filename)
        {
            var webClient = new Mock<IWebClient>();
            webClient
                .Setup(x => x.Headers)
                .Returns(new WebHeaderCollection());
            webClient
                .Setup(x => x.DownloadData(It.IsAny<string>()))
                .Returns(File.ReadAllBytes(string.Format("Fixtures/{0}.json", filename)));

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
    }
}
