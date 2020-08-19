// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;
using PasswordManagerAccess.OnePassword;
using Xunit;

namespace PasswordManagerAccess.Test.OnePassword
{
    public class SrpInfoTest
    {
        [Fact]
        public void SrpInfo_properties_are_set()
        {
            var srpMethod = "srp-method";
            var keyMethod = "key-method";
            var iterations = 1337;
            var salt = "salt".ToBytes();

            var session = new SrpInfo(srpMethod, keyMethod, iterations, salt);

            Assert.Equal(srpMethod, session.SrpMethod);
            Assert.Equal(keyMethod, session.KeyMethod);
            Assert.Equal(iterations, session.Iterations);
            Assert.Equal(salt, session.Salt);
        }
    }
}
