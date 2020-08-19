// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using Xunit;

namespace PasswordManagerAccess.Test.OnePassword
{
    public class AccountTest
    {
        [Fact]
        public void Account_needs_some_tests()
        {
            // TODO: It's quite difficult to make a test for these things as they rely on some encrypted
            //       blobs wrapped in json multiple times and are completely opaque. Figure out a better
            //       way to test it. This stuff is tested inside Client higher level tests.
        }
    }
}
