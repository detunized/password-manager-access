// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using Xunit;

namespace PasswordManagerAccess.Keeper.Test
{
    public class AccountTest
    {
        [Fact]
        public void Account_properties_are_set()
        {
            const string id = "id";
            const string name = "name";
            const string username = "username";
            const string password = "password";
            const string url = "url";
            const string note = "note";
            const string folder = "folder";
            var account = new Account(id, name, username, password, url, note, folder);

            Assert.Equal(id, account.Id);
            Assert.Equal(name, account.Name);
            Assert.Equal(username, account.Username);
            Assert.Equal(password, account.Password);
            Assert.Equal(url, account.Url);
            Assert.Equal(note, account.Note);
            Assert.Equal(folder, account.Folder);
        }
    }
}
