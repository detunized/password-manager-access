// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.LastPass;
using Xunit;

namespace PasswordManagerAccess.Test.LastPass
{
    public class VaultTest
    {
        [Fact]
        public void GenerateRandomClientId_returns_32_characters()
        {
            var id = Vault.GenerateRandomClientId();
            Assert.Equal(32, id.Length);
        }

        [Fact]
        public void GenerateRandomClientId_returns_different_ids()
        {
            var id1 = Vault.GenerateRandomClientId();
            var id2 = Vault.GenerateRandomClientId();

            Assert.NotEqual(id2, id1);
        }
    }
}
