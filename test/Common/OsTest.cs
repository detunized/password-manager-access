// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;
using Xunit;

namespace PasswordManagerAccess.Test.Common
{
    public class OsTest
    {
        [Fact]
        public void UnixSeconds_returns_timestamp_older_than_2020_01_01_00_00_00()
        {
            Assert.True(Os.UnixSeconds() > 1577836800);
        }

        [Fact]
        public void UnixMilliseconds_returns_timestamp_older_than_2020_01_01_00_00_00_000()
        {
            Assert.True(Os.UnixMilliseconds() > 1577836800000);
        }
    }
}
