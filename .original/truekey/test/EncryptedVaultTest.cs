// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using NUnit.Framework;

namespace TrueKey.Test
{
    [TestFixture]
    class EncryptedVaultTest
    {
        [Test]
        public void EncryptedVault_properties_are_set()
        {
            var salt = "salt".ToBytes();
            var key = "key".ToBytes();
            var accounts = new EncryptedAccount[0];
            var vault = new EncryptedVault(salt, key, accounts);

            Assert.That(vault.MasterKeySalt, Is.EqualTo(salt));
            Assert.That(vault.EncryptedMasterKey, Is.EqualTo(key));
            Assert.That(vault.EncryptedAccounts, Is.SameAs(accounts));
        }
    }
}
