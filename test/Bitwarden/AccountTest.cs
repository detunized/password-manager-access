// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using FluentAssertions;
using PasswordManagerAccess.Bitwarden;
using Xunit;

namespace PasswordManagerAccess.Test.Bitwarden
{
    public class AccountTest
    {
        [Fact]
        public void Account_properties_are_set()
        {
            // Arrange
            var item = new VaultItem
            {
                Id = "id",
                Name = "name",
                Note = "notes",
                DeletedDate = "deleted date",
                Folder = "folder",
                CollectionIds = ["collection1", "collection2"],
                HidePassword = true,
                CustomFields = [new CustomField("name1", "value1"), new CustomField("name2", "value2")],
            };

            // Act
            var account = new Account(item)
            {
                Username = "username",
                Password = "password",
                Url = "url",
                Totp = "totp",
            };

            // Assert

            // VaultItem properties
            account.Id.Should().Be("id");
            account.Name.Should().Be("name");
            account.Note.Should().Be("notes");
            account.DeletedDate.Should().Be("deleted date");
            account.Folder.Should().Be("folder");
            account.CollectionIds.Should().Equal("collection1", "collection2");
            account.HidePassword.Should().BeTrue();
            account.CustomFields.Should().Equal(new CustomField("name1", "value1"), new CustomField("name2", "value2"));

            // Account properties
            account.Username.Should().Be("username");
            account.Password.Should().Be("password");
            account.Url.Should().Be("url");
            account.Totp.Should().Be("totp");
        }
    }
}
