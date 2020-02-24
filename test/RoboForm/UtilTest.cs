// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.RoboForm;
using Xunit;

namespace PasswordManagerAccess.Test.RoboForm
{
    public class UtilTest
    {
        [Fact]
        public void RandomDeviceId_starts_with_B()
        {
            for (var i = 0; i < 10; ++i)
                Assert.StartsWith("B", Util.RandomDeviceId());
        }

        [Fact]
        public void RandomDeviceId_has_correct_length()
        {
            for (var i = 0; i < 10; ++i)
                Assert.Equal(33, Util.RandomDeviceId().Length);
        }

        [Fact]
        public void ComputeClientKey_returns_key()
        {
            // Generated with the original JavaScript code
            Assert.Equal("8sbDhSTLwbl0FhiHAxFxGUQvQwcr4JIbpExO64+Jj8o=".Decode64(),
                         Util.ComputeClientKey(TestData.Password, TestData.AuthInfo));
        }

        [Fact]
        public void HashPassword_returns_hashed_password()
        {
            // TODO: Generate a test case with MD5

            // Generated with the original JavaScript code
            Assert.Equal("b+rd7TUt65+hdE7+lHCBPPWHjxbq6qs0y7zufYfqHto=".Decode64(),
                         Util.HashPassword(TestData.Password, TestData.AuthInfo));
        }
    }
}
