// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Kaspersky;
using Xunit;

namespace PasswordManagerAccess.Test.Kaspersky
{
    public class AccountTest
    {
        [Fact]
        public void Account_properties_are_set()
        {
            var id = "id";
            var name = "name";
            var url = "url";
            var notes = "notes";
            var folder = "folder";
            var credentials = new[]
            {
                new Credentials("id1", "name1", "username1", "password1", "notes1"),
                new Credentials("id2", "name2", "username2", "password2", "notes2"),
                new Credentials("id3", "name3", "username3", "password3", "notes3"),
            };

            var account = new Account(id, name, url, notes, folder, credentials);

            Assert.Equal(id, account.Id);
            Assert.Equal(name, account.Name);
            Assert.Equal(url, account.Url);
            Assert.Equal(notes, account.Notes);
            Assert.Equal(folder, account.Folder);
            Assert.Equal(credentials, account.Credentials);
        }

        [Fact]
        public void Credentials_properties_are_set()
        {
            var id = "id";
            var name = "name";
            var username = "username";
            var password = "password";
            var notes = "notes";

            var credentials = new Credentials(id, name, username, password, notes);

            Assert.Equal(id, credentials.Id);
            Assert.Equal(name, credentials.Name);
            Assert.Equal(username, credentials.Username);
            Assert.Equal(password, credentials.Password);
            Assert.Equal(notes, credentials.Notes);
        }
    }
}
