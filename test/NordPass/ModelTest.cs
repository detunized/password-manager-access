// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Text.Json;
using PasswordManagerAccess.NordPass;
using Shouldly;
using Xunit;

namespace PasswordManagerAccess.Test.NordPass;

public class ModelTest : TestBase
{
    [Fact]
    public void Vault_deserializes_from_json()
    {
        // Arrange
        var json = GetFixture("vault");

        // Act
        var vault = JsonSerializer.Deserialize<Model.Vault>(json);

        // Assert
        vault.ShouldNotBeNull();
        vault.Identities.Length.ShouldBe(1);
        vault.VaultItems.Length.ShouldBe(11);
        vault.VaultItems.ShouldContain(i => i.Type == "folder");
        vault.VaultItems.ShouldContain(i => i.Type == "item");
        vault.VaultItems.ShouldContain(i => i.Type == "option");
    }
}
