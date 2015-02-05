// Copyright (C) 2015 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using NUnit.Framework;

namespace PasswordBox.Test
{
    [TestFixture]
    class VaultTest
    {
        [Test]
        public void Vault_is_created()
        {
            var vault = new Vault();
            Assert.NotNull(vault);
        }
    }
}
