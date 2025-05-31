// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Bitwarden;
using Shouldly;
using Xunit;

namespace PasswordManagerAccess.Test.Bitwarden
{
    public class SshKeyTest
    {
        [Fact]
        public void SshKey_properties_are_set()
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
            var sshKey = new SshKey(item)
            {
                PublicKey = "public key",
                PrivateKey = "private key",
                Fingerprint = "fingerprint",
            };

            // Assert

            // VaultItem properties
            sshKey.Id.ShouldBe("id");
            sshKey.Name.ShouldBe("name");
            sshKey.Note.ShouldBe("notes");
            sshKey.DeletedDate.ShouldBe("deleted date");
            sshKey.Folder.ShouldBe("folder");
            sshKey.CollectionIds.ShouldBe(["collection1", "collection2"]);
            sshKey.HidePassword.ShouldBeTrue();
            sshKey.CustomFields.ShouldBe([new CustomField("name1", "value1"), new CustomField("name2", "value2")]);

            // SshKey properties
            sshKey.PublicKey.ShouldBe("public key");
            sshKey.PrivateKey.ShouldBe("private key");
            sshKey.Fingerprint.ShouldBe("fingerprint");
        }
    }
}
