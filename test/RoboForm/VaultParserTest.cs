// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using Newtonsoft.Json.Linq;
using PasswordManagerAccess.RoboForm;
using Xunit;

namespace PasswordManagerAccess.Test.RoboForm
{
    public class VaultParserTest: TestBase
    {
        [Fact]
        public void Parse_returns_vault()
        {
            var vault = VaultParser.Parse(JObject.Parse(GetFixture("blob")));
            Assert.True(vault.Accounts.Length > 1);
        }
    }
}
