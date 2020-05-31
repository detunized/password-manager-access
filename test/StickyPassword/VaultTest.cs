// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.StickyPassword;
using Xunit;

namespace PasswordManagerAccess.Test.StickyPassword
{
    public class VaultTest
    {
        [Fact]
        public void Vault_GenerateRandomDeviceId_returns_id()
        {
            var id = Vault.GenerateRandomDeviceId();

            Assert.Matches("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", id);
        }

        [Fact]
        public void Vault_GenerateRandomDeviceId_returns_different_ids()
        {
            var id1 = Vault.GenerateRandomDeviceId();
            var id2 = Vault.GenerateRandomDeviceId();

            Assert.NotEqual(id1, id2);
        }
    }
}
