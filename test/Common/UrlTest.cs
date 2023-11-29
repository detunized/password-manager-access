// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;
using Xunit;

namespace PasswordManagerAccess.Test.Common
{
    public class UrlTest
    {
        [Theory]
        [InlineData("https://blah.com?param=single", "single")]
        [InlineData("https://blah.com?param=first&more=next", "first")]
        [InlineData("https://blah.com?first=blah&param=middle&more=next", "middle")]
        [InlineData("https://blah.com?first=blah&more=next&param=last", "last")]
        [InlineData("https://blah.com?param=", "")]
        [InlineData("https://blah.com?param=&more=next", "")]
        [InlineData("https://blah.com", null)]
        [InlineData("https://blah.com?", null)]
        [InlineData("https://blah.com?blah=none", null)]
        public void ExtractQueryParameter_returns_parameter_value(string url, string expected)
        {
            var v = Url.ExtractQueryParameter(url, "param");
            Assert.Equal(expected, v);
        }
    }
}
