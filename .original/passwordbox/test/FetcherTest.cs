// Copyright (C) 2015 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using Moq;
using NUnit.Framework;

namespace PasswordBox.Test
{
    [TestFixture]
    class FetcherTest
    {
        private const string Username = "username";
        private const string Password = "password";

        [Test]
        public void Login_returns_valid_session()
        {
            var webClient = new Mock<IWebClient>();
            var session = Fetcher.Login(Username, Password, webClient.Object);

            Assert.NotNull(session);
            Assert.AreEqual("", session.Id);
        }
    }
}
