// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.IO;
using Moq;
using NUnit.Framework;

namespace TrueKey.Test
{
    [TestFixture]
    class RemoteTest
    {
        [Test]
        public void RegisetNewDevice_returns_device_info()
        {
            var client = SetupPostWithFixture("register-new-device-response");
            var result = Remote.RegisetNewDevice("truekey-sharp", client.Object);

            Assert.That(result.Token, Is.StringStarting("AQCmAwEA"));
            Assert.That(result.Id, Is.StringStarting("d871347b"));
        }

        //
        // Helpers
        //

        private static Mock<IHttpClient> SetupPost(string response)
        {
            var mock = new Mock<IHttpClient>();
            mock.Setup(x => x.Post(It.IsAny<string>(),
                                   It.IsAny<Dictionary<string, string>>()))
                .Returns(response);
            return mock;
        }

        private static Mock<IHttpClient> SetupPostWithFixture(string name)
        {
            return SetupPost(File.ReadAllText(string.Format("Fixtures/{0}.json", name)));
        }
    }
}
