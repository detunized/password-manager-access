// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Duo;
using Xunit;

namespace PasswordManagerAccess.Test.Duo
{
    public class UtilTest
    {
        [Fact]
        public void Parse_returns_parsed_document()
        {
            var doc = Util.Parse("<html></html>");

            Assert.NotNull(doc);
        }

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
            var v = Util.ExtractQueryParameter(url, "param");
            Assert.Equal(expected, v);
        }
    }
}
