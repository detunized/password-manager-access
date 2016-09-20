// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.IO;
using NUnit.Framework;

namespace ZohoVault.Test
{
    public class VaultTest
    {
        [Test]
        public void Open_with_json_returns_vault()
        {
            var json = File.ReadAllBytes(string.Format("Fixtures/{0}.json", "vault-response")).ToUtf8();
            var vault = Vault.Open(json, TestData.Passphrase);
            Assert.That(vault.Accounts, Is.EqualTo(new[] {"facebook", "microsoft"}));
        }
    }
}
