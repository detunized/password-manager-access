// Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Linq;
using NUnit.Framework;

namespace LastPass.Test
{
    [TestFixture]
    class VaultTest
    {
        //
        // TODO: Figure out how to test this!
        //       All methods require username/password which I don't want to expose here.
        //       Actually, I'm pretty sure the password is lost and the whole test blob
        //       needs to be regenerated.
        //       Currently all the vault tests are disabled.
        //

        //[Test]
        public void Create_returns_vault_with_correct_accounts()
        {
            var vault = Vault.Create(new Blob(TestData.Blob, 1), "", "");
            Assert.AreEqual(TestData.Accounts.Length, vault.Accounts.Length);
            Assert.AreEqual(TestData.Accounts.Select(i => i.Id), vault.Accounts.Select(i => i.Id));
            Assert.AreEqual(TestData.Accounts.Select(i => i.Url), vault.Accounts.Select(i => i.Url));
        }
    }
}
