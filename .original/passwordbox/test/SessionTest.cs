// Copyright (C) 2015 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using NUnit.Framework;

namespace PasswordBox.Test
{
    [TestFixture]
    class SessionTest
    {
        [Test]
        public void Session_properties_are_set()
        {
            var id = "12345678";
            var key = "deadbeef".DecodeHex();

            var session = new Session(id, key);

            Assert.AreEqual(id, session.Id);
            Assert.AreEqual(key, session.Key);
        }
    }
}
