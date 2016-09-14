// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Specialized;
using System.Net;
using Moq;
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
        public void Login_throws_on_error()
        {
            Assert.That(
                () => Remote.Login(Username, Password, SetupWebClient("showerror('It failed')").Object),
                Throws.TypeOf<InvalidOperationException>());
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
            var responseHeaders = new WebHeaderCollection();
            responseHeaders[HttpResponseHeader.SetCookie] = string.Format("IAMAUTHTOKEN={0};", Token);

            var webClient = new Mock<IWebClient>();
            webClient
                .Setup(x => x.Headers)
                .Returns(new WebHeaderCollection());
            webClient
                .Setup(x => x.ResponseHeaders)
                .Returns(responseHeaders);
            webClient
                .Setup(x => x.UploadValues(It.IsAny<string>(), It.IsAny<NameValueCollection>()))
                .Returns(response.ToBytes());

            return webClient;
        }

        private static Mock<IWebClient> SetupWebClient(Exception e)
        {
            var webClient = new Mock<IWebClient>();
            webClient
                .Setup(x => x.UploadValues(It.IsAny<string>(), It.IsAny<NameValueCollection>()))
                .Throws(e);

            return webClient;
        }
    }
}
