// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Kdbx;
using Xunit;

namespace PasswordManagerAccess.Test.Kdbx
{
    public class ParserTest: TestBase
    {
        [Fact]
        public void Parse_works()
        {
            var blob = GetBinaryFixture("kdbx4-aes-aes", "kdbx");
            Parser.Parse(blob, "password");
        }
    }
}
