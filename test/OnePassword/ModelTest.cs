// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Text.Json;
using PasswordManagerAccess.OnePassword;
using Xunit;

namespace PasswordManagerAccess.Test.OnePassword
{
    public class ModelTest : TestBase
    {
        [Fact]
        public void VaultItemDetails_parses_with_all_types_of_fields()
        {
            // Arrange
            var json = GetFixture("vault-item-with-lots-of-fields");

            // Act
            var details = JsonSerializer.Deserialize<Model.VaultItemDetails>(json);

            // Assert
            Assert.Equal(2, details.Sections!.Length);
            Assert.Equal(6, details.Sections[0].Fields!.Length);
            Assert.Equal(6, details.Sections[1].Fields!.Length);
        }
    }
}
