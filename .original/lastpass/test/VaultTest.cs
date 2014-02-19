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

        //[Test]
        public void DecryptAllAccounts_decrypts_all_accounts()
        {
            var vault = Vault.Create(new Blob(TestData.Blob, 1), "", "");
            vault.DecryptAllAccounts(Account.Field.Name |
                                     Account.Field.Username |
                                     Account.Field.Password |
                                     Account.Field.Group,
                                     "p8utF7ZB8yD06SrtrD4hsdvEOiBU1Y19cr2dhG9DWZg=".Decode64());
            for (var i = 0; i < vault.Accounts.Length; ++i)
            {
                var account = vault.Accounts[i];
                var expectedAccount = TestData.Accounts[i];
                Assert.AreEqual(expectedAccount.Id, account.Id);
                Assert.AreEqual(expectedAccount.Name, account.Name.Decrypted);
                Assert.AreEqual(expectedAccount.Username, account.Username.Decrypted);
                Assert.AreEqual(expectedAccount.Password, account.Password.Decrypted);
                Assert.AreEqual(expectedAccount.Url, account.Url);
                Assert.AreEqual(expectedAccount.Group, account.Group.Decrypted);
            }
        }

        //[Test]
        public void GetAccount_returns_corrent_account()
        {
            var vault = Vault.Create(new Blob(TestData.Blob, 1), "", "");
            Assert.AreEqual("1872745596", vault.GetAccount("1872745596").Id);
            Assert.AreEqual("1872746606", vault.GetAccount("1872746606").Id);
            Assert.AreEqual("1872746006", vault.GetAccount("1872746006").Id);
        }

        //[Test]
        [ExpectedException(typeof(InvalidOperationException))]
        public void GetAccount_throws_on_invalid_id()
        {
            var vault = Vault.Create(new Blob(TestData.Blob, 1), "", "");
            var account = vault.GetAccount("Doesn't exist");
        }
    }
}
