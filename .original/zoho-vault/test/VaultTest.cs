// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.IO;
using Newtonsoft.Json.Linq;
using NUnit.Framework;

namespace ZohoVault.Test
{
    public class VaultTest
    {
        [Test]
        public void Open_with_json_returns_vault()
        {
            var json = File.ReadAllBytes(string.Format("Fixtures/{0}.json", "vault-response")).ToUtf8();
            var parsed = JObject.Parse(json);
            var vault = Vault.Open(parsed, TestData.Key);
            var accounts = vault.Accounts;

            Assert.That(accounts.Length, Is.EqualTo(2));

            Assert.That(accounts[0].Id, Is.EqualTo("30024000000008008"));
            Assert.That(accounts[0].Name, Is.EqualTo("facebook"));
            Assert.That(accounts[0].Username, Is.EqualTo("mark"));
            Assert.That(accounts[0].Password, Is.EqualTo("zuckerberg"));
            Assert.That(accounts[0].Url, Is.EqualTo("http://facebook.com"));
            Assert.That(accounts[0].Note, Is.EqualTo(""));

            Assert.That(accounts[1].Id, Is.EqualTo("30024000000008013"));
            Assert.That(accounts[1].Name, Is.EqualTo("microsoft"));
            Assert.That(accounts[1].Username, Is.EqualTo("bill"));
            Assert.That(accounts[1].Password, Is.EqualTo("gates"));
            Assert.That(accounts[1].Url, Is.EqualTo("http://microsoft.com"));
            Assert.That(accounts[1].Note, Is.EqualTo(""));
        }
    }
}
