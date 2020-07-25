// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;
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

        [Fact]
        public void DecryptItemVersion92_decrypts_item()
        {
            var blob =
                "AwAAAHja7Vdbc6pIEP4vvOakRAXEU5WHGRiJERRUSMjWqS2EAUZuyjWa8r8fyG5ysoZUadXZWmsr88Clp7/u5usZpvuZsvI8Jasixxn1/Y9nyrFyi/r+TK3CZPUicAkOnba5Ljtkej2aZXp9nv1G5bsNroWHb1RsRfVTo42VxCG1AYc6fDuGu1aY4VdY7xeMZCLepNiu0W2wPC3aUSi2093mTJBBMrIKcQuEbvmiEqcZSWLq8ONNFP1pJ1GE4/zFxIVx9TnsvyLLwa5VhLmceCT+YuwUxryCOF9MncIUsZOvNXUaUxko8sSyc1JaOfli7VTWRlaZpCTH/x++Pkf9FsIkHOO0CXjayC6QtYurJuILJerytuPGSuuyS0qTYiNd6Bl5caurSMMvnk7jCWw24W7ZaDczf8HYX7BNmmxwmhOcKTi3Xtyc6e/f3pm+lYm1opDE+Wt7ciKBMrFxnJ2d4BCfmSjQFCD4LC+LXWz7aRKT/Xmu3uPekvrpLqBoEbE000XXiOHRNUP32GvID9G1KNC9LgBDBAcs9eqIPrSV68cW/x7XLZfX0W6x7T/324x/6MeOLEdppMwCj5b9K9XwOCGeaygfjB9mIVm6D3dw2N2P5YWapcqDVQbJfYDiUrGQat3Kt0wU6QWzlKaTcr3eFgQ+zhn+cRw42s3NWzT9Q9vh988o4iIMW/Xft95HgRMDzuYVPZG8BNRjutB9pHv1E2xegSYAs7m7fGfov0gepos5PQZpxtic1gjmsaZ3a23haV2VvKnpjfDORv6jXQEgZkr9OhCB7ZRbqQEI+kKfQ0P0VfMKbiw3VAXLKoCdDjvuEJqqfBfsyISXpAzWIZExnflVptqe2uuvyr7a66SGr005SEpgo9QIINvpdFxXVaQ9cu5FfoxKE8w0YPrcDm3FWdofmLNJECEwQbQHuPFUk00DBgIk2wr7t8jywBPIyd1AmEdrCYjCYjd0vGgrAqny10z1JALoB1IfsR7OoC+o9x2mmQM4YaVZCcUXXlA4WgaLQosEoT1pb23XUQZmrJnQoy2ZF9vAXctKWATG4H7EArFm0ZNCutjzworIcFcsO7DiSpX0VQ7uc/So9HtjnjdZp2QLYc9Bg1T9ACTTTliJc0GQsBKb3K292ju23zUG2ifL6fW0OwpsrpZOJrGok0yJP7EKcxLoOpRHm2UVZRF0ASsNLdm7c+HUNhB0XS4okkCccWNVSW93+ZWv6xwS781tOpIfB7qzZhZ5dfN5EO+OkpN/dR/ajdNhH4vu07HHfeGPw0+s9YS/";

            Client.DecryptItemVersion92(blob.Decode64());
        }
    }
}
