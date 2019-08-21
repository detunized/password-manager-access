// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Dashlane;
using Xunit;

namespace PasswordManagerAccess.Test.Dashlane
{
    public class UkiTest
    {
        [Fact]
        public void Generate_returns_uki()
        {
            Assert.Matches(@"[0-9a-f]+-webaccess-[0-9]+", Uki.Generate());
        }
    }
}
