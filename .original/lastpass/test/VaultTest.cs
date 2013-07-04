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
            Assert.AreEqual(TestData.Accounts.Select(i => i.Id), vault.EncryptedAccounts.Select(i => i.Id));
            Assert.AreEqual(TestData.Accounts.Select(i => i.Url), vault.EncryptedAccounts.Select(i => i.Url));
        }

        [Test]
        public void DecryptAccount_decrypts_accounts()
        {
            var vault = Vault.Create(new Blob(TestData.Blob, 1));
            for (var i = 0; i < vault.EncryptedAccounts.Length; ++i)
            {
                var account = vault.DecryptAccount(vault.EncryptedAccounts[i],
                                                   "p8utF7ZB8yD06SrtrD4hsdvEOiBU1Y19cr2dhG9DWZg=".Decode64());
                var expectedAccount = TestData.Accounts[i];
                Assert.AreEqual(expectedAccount.Id, account.Id);
                Assert.AreEqual(expectedAccount.Name, account.Name);
                Assert.AreEqual(expectedAccount.Username, account.Username);
                Assert.AreEqual(expectedAccount.Password, account.Password);
                Assert.AreEqual(expectedAccount.Url, account.Url);
            }
        }
    }
}
