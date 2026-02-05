// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.NordPass;
using Xunit;

namespace PasswordManagerAccess.Test.NordPass;

public class VaultTest
{
    [Fact]
    public void Open_returns_vault()
    {
        var vault = Vault.Open("username", "password");

        Assert.NotNull(vault);
        Assert.NotNull(vault.Accounts);
    }
}
