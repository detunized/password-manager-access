// Copyright (C) 2015 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using NUnit.Framework;

namespace PasswordBox.Test
{
    [TestFixture]
    class SessionTest
    {
        [Test]
        public void Session_id_is_set()
        {
            var id = "12345678";
            var session = new Session(id);
            Assert.AreEqual(id, session.Id);
        }
    }
}
