// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Bitwarden;
using Shouldly;
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
            account.Id.ShouldBe("id");
            account.Name.ShouldBe("name");
            account.Note.ShouldBe("notes");
            account.Folder.ShouldBe("folder");
            account.CollectionIds.ShouldBe(["collection1", "collection2"]);
            account.HidePassword.ShouldBeTrue();
            account.CustomFields.ShouldBe([new CustomField("name1", "value1"), new CustomField("name2", "value2")]);

            // Account properties
            account.Username.ShouldBe("username");
            account.Password.ShouldBe("password");
            account.Url.ShouldBe("url");
            account.Totp.ShouldBe("totp");
        }
    }
}
