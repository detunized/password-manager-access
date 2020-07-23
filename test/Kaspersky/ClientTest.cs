// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Kaspersky;
using Xunit;

namespace PasswordManagerAccess.Test.Kaspersky
{
    public class ClientTest
    {
        [Fact]
        public void GetHost_returns_domain()
        {
            var host = Client.GetHost("https://bosh4.ucp-ntfy.kaspersky-labs.com/find_bosh_bind");

            Assert.Equal("bosh4.ucp-ntfy.kaspersky-labs.com", host);
        }

        [Fact]
        public void GetNotifyServerIndex_returns_index()
        {
            var index = Client.GetNotifyServerIndex("206a9e27-f96a-44d5-ac0d-84efe4f1835a");

            Assert.Equal("39", index);
        }

        [Fact]
        public void GetParentHost_returns_parent_domain()
        {
            var domain = Client.GetParentHost("bosh4.ucp-ntfy.kaspersky-labs.com");

            Assert.Equal("ucp-ntfy.kaspersky-labs.com", domain);
        }
    }
}
