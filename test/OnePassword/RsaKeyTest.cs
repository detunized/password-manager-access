// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.OnePassword;
using Xunit;
using R = PasswordManagerAccess.OnePassword.Response;

namespace PasswordManagerAccess.Test.OnePassword
{
    public class RsaKeyTest: TestBase
    {
        [Fact]
        public void Parse_returns_key()
        {
            var key = RsaKey.Parse(RsaKeyData);
            Assert.Equal("szerdhg2ww2ahjo4ilz57x7cce", key.Id);
        }

        //
        // Data
        //

        private readonly R.RsaKey RsaKeyData; // Has to be initialized from the constructor

        public RsaKeyTest()
        {
            RsaKeyData = ParseFixture<R.RsaKey>("rsa-key");
        }
    }
}
