// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using FluentAssertions;
using PasswordManagerAccess.Bitwarden;
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
                Notes = "notes",
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
            sshKey.Id.Should().Be("id");
            sshKey.Name.Should().Be("name");
            sshKey.Notes.Should().Be("notes");
            sshKey.DeletedDate.Should().Be("deleted date");
            sshKey.Folder.Should().Be("folder");
            sshKey.CollectionIds.Should().Equal("collection1", "collection2");
            sshKey.HidePassword.Should().BeTrue();
            sshKey.CustomFields.Should().Equal(new CustomField("name1", "value1"), new CustomField("name2", "value2"));
            // SshKey properties
            sshKey.PublicKey.Should().Be("public key");
            sshKey.PrivateKey.Should().Be("private key");
            sshKey.Fingerprint.Should().Be("fingerprint");
        }
    }
}
