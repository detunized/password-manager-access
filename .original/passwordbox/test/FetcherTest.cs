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

        [Test]
        public void ComputePasswordHash_returns_correct_result()
        {
            // Test data is generated with the PasswordBox JavaScript sources
            var hash = Fetcher.ComputePasswordHash("username", "password");
            Assert.AreEqual("bb5eeb368dd3d7ba5ab371c76ba5073e0a91f55697b81790bb34846d3e25f8e4", hash);
        }

        [Test]
        public void HexSha1_returns_correct_result()
        {
            // Test data is from http://www.nsrl.nist.gov/testdata/
            var hash = Fetcher.Sha1Hex("abc");
            Assert.AreEqual("a9993e364706816aba3e25717850c26c9cd0d89d", hash);
        }
    }
}
