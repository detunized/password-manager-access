// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Specialized;
using System.Net;
using System.Text;
using Moq;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using NUnit.Framework;

namespace ZohoVault.Test
{
    [TestFixture]
    class RemoteTest
    {
        public const string Username = "username";
        public const string Password = "password";
        public const string Token = "<token>";

        [Test]
        public void Login_returns_token()
        {
            Assert.That(
                Remote.Login(Username, Password, SetupWebClient("showsuccess('It worked')").Object),
                Is.EqualTo(Token));
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

        private static Mock<IWebClient> SetupWebClient(string response = "{}")
        {
            var webClient = new Mock<IWebClient>();
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
