// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.OnePassword;
using Xunit;

namespace PasswordManagerAccess.Test.OnePassword
{
    public class CredentialsTest
    {
        [Fact]
        public void ParsedAccountKey_updated_when_account_key_changes()
        {
            var credentials = new Credentials { AccountKey = "A3-ABCDEF-GGGGGG-HHHHH-IIIII-JJJJJ-KKKKK" };

            Assert.Equal("A3", credentials.ParsedAccountKey.Format);
            Assert.Equal("ABCDEF", credentials.ParsedAccountKey.Uuid);
            Assert.Equal("GGGGGGHHHHHIIIIIJJJJJKKKKK", credentials.ParsedAccountKey.Key);

            credentials.AccountKey = "A3-PQRSTU-VVVVVV-WWWWW-XXXXX-YYYYY-ZZZZZ";

            Assert.Equal("A3", credentials.ParsedAccountKey.Format);
            Assert.Equal("PQRSTU", credentials.ParsedAccountKey.Uuid);
            Assert.Equal("VVVVVVWWWWWXXXXXYYYYYZZZZZ", credentials.ParsedAccountKey.Key);
        }
    }
}
