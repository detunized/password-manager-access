// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using Xunit;
using PasswordManagerAccess.Bitwarden;

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
            var deleteddate = "deleteddate";
            var account = new Account(id, name, username, password, url, note, totp, deleteddate, folder);

            Assert.Equal(id, account.Id);
            Assert.Equal(name, account.Name);
            Assert.Equal(username, account.Username);
            Assert.Equal(password, account.Password);
            Assert.Equal(url, account.Url);
            Assert.Equal(note, account.Note);
            Assert.Equal(totp, account.Totp);
            Assert.Equal(deleteddate, account.DeletedDate);
            Assert.Equal(folder, account.Folder);
        }
    }
}
