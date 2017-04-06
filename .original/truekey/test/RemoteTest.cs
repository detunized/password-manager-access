// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
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
            // TODO: Use actual response example
            var client = SetupPost("{clientToken: 'token', tkDeviceId: 'id'}");
            var result = Remote.RegisetNewDevice("truekey-sharp", client.Object);

            Assert.That(result.Token, Is.EqualTo("token"));
            Assert.That(result.Id, Is.EqualTo("id"));
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
    }
}
