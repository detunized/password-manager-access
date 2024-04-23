// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Threading;
using FluentAssertions;
using PasswordManagerAccess.ProtonPass;
using Xunit;

namespace PasswordManagerAccess.Test.ProtonPass
{
    public class VaultTest: TestBase
    {
        [Fact(Skip = "TODO: need to add a flow of requests")]
        public async void Open_returns_a_vault()
        {
            var vault = await Vault.Open("username",
                                         "password",
                                         null!,
                                         null!,
                                         new RestFlow(),
                                         new CancellationTokenSource().Token);
            vault.Should().NotBeNull();
        }
    }
}
