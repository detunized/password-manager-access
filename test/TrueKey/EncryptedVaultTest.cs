// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.TrueKey;
using Xunit;

namespace PasswordManagerAccess.Test.TrueKey
{
    public class EncryptedVaultTest
    {
        [Fact]
        public void EncryptedVault_properties_are_set()
        {
            var salt = "salt".ToBytes();
            var key = "key".ToBytes();
            var accounts = new EncryptedAccount[0];
            var vault = new EncryptedVault(salt, key, accounts);

            Assert.Equal(salt, vault.MasterKeySalt);
            Assert.Equal(key, vault.EncryptedMasterKey);
            Assert.Same(accounts, vault.EncryptedAccounts);
        }
    }
}
