// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;
using PasswordManagerAccess.Kdbx;
using Xunit;

namespace PasswordManagerAccess.Test.Kdbx
{
    public class UtilTest
    {
        [Theory]
        [InlineData("",
                    "",
                    "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=")]
        [InlineData("password",
                    "",
                    "c2Qcmfdxn1fY9L6xGjA6/NGQJDpRzth4LKbT2+AU0UY=")]
        [InlineData("",
                    "qYcgDd8vqIY7JlMPfNxdksWGVhpooSGOnh9bFFEbq5Q=",
                    "AURDnmuQFyEbjTZ2HfigcKvMorpeyWSXAbqfKs16v/U=")]
        [InlineData("password",
                    "qYcgDd8vqIY7JlMPfNxdksWGVhpooSGOnh9bFFEbq5Q=",
                    "+0dAIBzDDLIer72hVh++t+wdi5kE5TFCEfu76vjzdxM=")]
        public void ComposeMasterKey_returns_composite_key(string password, string keyfile, string expected)
        {
            var key = Util.ComposeMasterKey(password, keyfile.Decode64());
            Assert.Equal(expected.Decode64(), key);
        }

        [Fact]
        public void ComposeMasterKey_throws_on_invalid_keyfile_length()
        {
            Exceptions.AssertThrowsInternalError(() => Util.ComposeMasterKey("password", "invalid".ToBytes()),
                                                 "Key file must be 32 bytes long");
        }
    }
}
