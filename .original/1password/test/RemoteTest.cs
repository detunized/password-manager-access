// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.IO;
using Moq;
using NUnit.Framework;

namespace OnePassword.Test
{
    [TestFixture]
    public class RemoteTest
    {
        [Test]
        public void StartNewSession_returns_session()
        {
            var client = SetupGetWithFixture("start-new-session-response");
            var session = Remote.StartNewSession(TestData.ClientInfo, client.Object);

            Assert.That(session.Id, Is.EqualTo(TestData.SessionId));
        }

        //
        // Helpers
        //

        private static Mock<IHttpClient> SetupGetWithFixture(string name)
        {
            return SetupGet(ReadFixture(name));
        }

        private static Mock<IHttpClient> SetupGet(string response)
        {
            var mock = new Mock<IHttpClient>();
            mock.Setup(x => x.Get(It.IsAny<string>(),
                                  It.IsAny<Dictionary<string, string>>()))
                .Returns(response);
            return mock;
        }

        private static string ReadFixture(string name)
        {
            return File.ReadAllText(string.Format("Fixtures/{0}.json", name));
        }
    }
}
