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
    }
}
