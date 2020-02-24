// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using NUnit.Framework;

namespace PasswordManagerAccess.Test.RoboForm
{
    [TestFixture]
    class SessionTest
    {
        [Test]
        public void Token_is_set()
        {
            Assert.That(new Session("token", "").Token, Is.EqualTo("token"));
        }

        [Test]
        public void DeviceId_is_set()
        {
            Assert.That(new Session("", "device-id").DeviceId, Is.EqualTo("device-id"));
        }

        [Test]
        public void Header_is_set()
        {
            Assert.That(new Session("token", "device-id").Header,
                        Is.EqualTo("sib-auth=token; sib-deviceid=device-id"));
        }
    }
}
