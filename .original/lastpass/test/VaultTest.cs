using System.Linq;
using NUnit.Framework;

namespace LastPass.Test
{
    [TestFixture]
    class VaultTest
    {
        [Test]
        public void Create_returns_vault_with_correct_accounts()
        {
            var vault = Vault.Create(new Blob(TestData.Blob, 1));
            Assert.AreEqual(TestData.Accounts.Length, vault.EncryptedAccounts.Length);
            Assert.AreEqual(TestData.Accounts.Select(i => i.Url), vault.EncryptedAccounts.Select(i => i.Url));
        }

        [Test]
        public void DecryptAccount_decrypts_account()
        {
            var vault = Vault.Create(new Blob(TestData.Blob, 1));
            var account = vault.DecryptAccount(vault.EncryptedAccounts[0], "", "");
            Assert.AreEqual("", account.Name);
            Assert.AreEqual("", account.Username);
            Assert.AreEqual("", account.Password);
            Assert.AreEqual(TestData.Accounts[0].Url, account.Url);
        }
    }
}
