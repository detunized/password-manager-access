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
            Assert.AreEqual(TestData.Accounts.Length, vault.Accounts.Length);
            Assert.AreEqual(TestData.Accounts.Select(i => i.Url), vault.Accounts.Select(i => i.Url));
        }
    }
}
