// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using Newtonsoft.Json.Linq;
using PasswordManagerAccess.ZohoVault;
using Xunit;
using R = PasswordManagerAccess.ZohoVault.Response;

namespace PasswordManagerAccess.Test.ZohoVault
{
    public class VaultTest: TestBase
    {
        [Fact]
        public void Open_with_json_returns_vault()
        {
            var parsed = JObject.Parse(GetFixture("vault-response"))["operation"]["details"].ToObject<R.Vault>();
            var vault = Vault.Open(parsed, TestData.Key);
            var accounts = vault.Accounts;

            Assert.Equal(2, accounts.Length);

            Assert.Equal("30024000000008008", accounts[0].Id);
            Assert.Equal("facebook", accounts[0].Name);
            Assert.Equal("mark", accounts[0].Username);
            Assert.Equal("zuckerberg", accounts[0].Password);
            Assert.Equal("http://facebook.com", accounts[0].Url);
            Assert.Equal("", accounts[0].Note);

            Assert.Equal("30024000000008013", accounts[1].Id);
            Assert.Equal("microsoft", accounts[1].Name);
            Assert.Equal("bill", accounts[1].Username);
            Assert.Equal("gates", accounts[1].Password);
            Assert.Equal("http://microsoft.com", accounts[1].Url);
            Assert.Equal("", accounts[1].Note);
        }
    }
}
