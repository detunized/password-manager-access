// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using FluentAssertions;
using PasswordManagerAccess.ProtonPass;
using Xunit;

namespace PasswordManagerAccess.Test.ProtonPass
{
    public class VaultTest: TestBase
    {
        [Fact]
        public async void Open_returns_a_vault()
        {
            var vault = await Vault.Open("username", "password");
            vault.Should().NotBeNull();
        }
    }
}
