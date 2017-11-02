// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using NUnit.Framework;

namespace RoboForm.Test
{
    [TestFixture]
    public class ClientTest
    {
        [Test]
        public void Step1AuthorizationHeader_returns_header()
        {
            var expected = "SibAuth realm=\"RoboForm Online Server\",data=\"biwsbj1sYXN0cGFzcy" +
                           "5ydWJ5QGdtYWlsLmNvbSxyPS1EZUhSclpqQzhEWl8wZThSR3Npc2c=\"";
            var header = Client.Step1AuthorizationHeader("lastpass.ruby@gmail.com",
                                                         "-DeHRrZjC8DZ_0e8RGsisg");
            Assert.That(header, Is.EqualTo(expected));
        }
    }
}
