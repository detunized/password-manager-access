// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Bitwarden;
using Xunit;

namespace PasswordManagerAccess.Test.Bitwarden
{
    public class AccountTest
    {
        [Fact]
        public void Account_properties_are_set()
        {
            var id = "id";
            var name = "name";
            var username = "username";
            var password = "password";
            var url = "url";
            var note = "note";
            var folder = "folder";
            var totp = "totp";
            var deletedDate = "deleted date";
            var collections = new[] { "collection1", "collection2" };
            var hidePassword = true;
            var customFields = new[] { new CustomField("name1", "value1"), new CustomField("name2", "value2") };

            var account = new Account(
                id: id,
                name: name,
                username: username,
                password: password,
                url: url,
                note: note,
                totp: totp,
                deletedDate: deletedDate,
                folder: folder,
                collectionIds: collections,
                hidePassword: hidePassword,
                customFields: customFields
            );

            Assert.Equal(id, account.Id);
            Assert.Equal(name, account.Name);
            Assert.Equal(username, account.Username);
            Assert.Equal(password, account.Password);
            Assert.Equal(url, account.Url);
            Assert.Equal(note, account.Note);
            Assert.Equal(totp, account.Totp);
            Assert.Equal(deletedDate, account.DeletedDate);
            Assert.Equal(folder, account.Folder);
            Assert.Same(collections, account.CollectionIds);
            Assert.Equal(hidePassword, account.HidePassword);
            Assert.Same(customFields, account.CustomFields);
        }
    }
}
