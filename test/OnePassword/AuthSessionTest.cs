// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;
using PasswordManagerAccess.OnePassword;
using Xunit;

namespace PasswordManagerAccess.Test.OnePassword
{
    public class AuthSessionTest
    {
        [Fact]
        public void AuthSession_properties_are_set()
        {
            var keyFormat = "key-format";
            var keyUuid = "key-uuid";
            var srpMethod = "srp-method";
            var keyMethod = "key-method";
            var iterations = 1337;
            var salt = "salt".ToBytes();

            var session = new AuthSession(keyFormat, keyUuid, srpMethod, keyMethod, iterations, salt);

            Assert.Equal(keyFormat, session.KeyFormat);
            Assert.Equal(keyUuid, session.KeyUuid);
            Assert.Equal(srpMethod, session.SrpMethod);
            Assert.Equal(keyMethod, session.KeyMethod);
            Assert.Equal(iterations, session.Iterations);
            Assert.Equal(salt, session.Salt);
        }
    }
}
