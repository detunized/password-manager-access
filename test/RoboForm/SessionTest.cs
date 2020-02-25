// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.RoboForm;
using Xunit;

namespace PasswordManagerAccess.Test.RoboForm
{
    public class SessionTest
    {
        [Fact]
        public void Token_is_set()
        {
            Assert.Equal("token", new Session("token", "").Token);
        }

        [Fact]
        public void DeviceId_is_set()
        {
            Assert.Equal("device-id", new Session("", "device-id").DeviceId);
        }

        [Fact]
        public void Cookies_are_set()
        {
            var session = new Session("token", "device-id");

            Assert.Equal(2, session.Cookies.Count);
            Assert.Equal("token", session.Cookies["sib-auth"]);
            Assert.Equal("device-id", session.Cookies["sib-deviceid"]);
        }
    }
}
