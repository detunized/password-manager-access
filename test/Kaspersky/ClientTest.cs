// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Net;
using PasswordManagerAccess.Kaspersky;
using Xunit;

namespace PasswordManagerAccess.Test.Kaspersky
{
    public class ClientTest
    {
        [Fact]
        public void Login_throws_on_invalid_credentials()
        {
            var flow = new RestFlow()
                .Post("{'Status':'', 'LogonContext': 'blah'}")
                .Post("{'Status': 'InvalidRegistrationData'}", HttpStatusCode.Unauthorized);

            Exceptions.AssertThrowsBadCredentials(() => Client.Login("username", "password", flow),
                                                  "username or password is incorrect");
        }

        [Fact]
        public void ConvertHttpsBoshUrlToWss_returns_wss_url()
        {
            var wss = Client.ConvertHttpsBoshUrlToWss("https://bosh5.ucp-ntfy.kaspersky-labs.com/http-bind");

            Assert.Equal("wss://bosh5.ucp-ntfy.kaspersky-labs.com/ws", wss);
        }

        [Fact]
        public void GetHost_returns_domain()
        {
            var host = Client.GetHost("https://bosh4.ucp-ntfy.kaspersky-labs.com/find_bosh_bind");

            Assert.Equal("bosh4.ucp-ntfy.kaspersky-labs.com", host);
        }

        [Theory]
        [InlineData("", 0)]
        [InlineData("1337", 98)]
        [InlineData("blah-blah-blah", 5)]
        [InlineData("206a9e27-f96a-44d5-ac0d-84efe4f1835a", 39)]
        public void GetNotifyServerIndex_returns_index(string userId, int expected)
        {
            var index = Client.GetNotifyServerIndex(userId);

            Assert.Equal(expected, index);
        }

        [Fact]
        public void GetParentHost_returns_parent_domain()
        {
            var domain = Client.GetParentHost("bosh4.ucp-ntfy.kaspersky-labs.com");

            Assert.Equal("ucp-ntfy.kaspersky-labs.com", domain);
        }
    }
}
