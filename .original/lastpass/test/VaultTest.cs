using NUnit.Framework;

namespace LastPass.Test
{
    [TestFixture]
    class VaultTest
    {
        [Test]
        public void Create_returns_vault()
        {
            var vault = Vault.Create(new Blob(TestData.Blob, 1));
            Assert.NotNull(vault);
        }
    }
}
