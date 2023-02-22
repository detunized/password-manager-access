// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.LastPass;
using Xunit;

namespace PasswordManagerAccess.Test.LastPass
{
    public class AccountTest
    {
        [Fact]
        public void EncryptedAccount_properties_are_set()
        {
            var id = "1234567890";
            var name = "name";
            var username = "username";
            var password = "password";
            var url = "url";
            var path = "path/to/item";
            var notes = "note";
            var isFavorite = true;
            var isShared = true;

            var account = new Account(id: id,
                                      name: name,
                                      username: username,
                                      password: password,
                                      url: url,
                                      path: path,
                                      notes: notes,
                                      isFavorite: isFavorite,
                                      isShared: isShared);

            Assert.Equal(id, account.Id);
            Assert.Equal(name, account.Name);
            Assert.Equal(username, account.Username);
            Assert.Equal(password, account.Password);
            Assert.Equal(url, account.Url);
            Assert.Equal(path, account.Path);
            Assert.Equal(notes, account.Notes);
            Assert.Equal(isFavorite, account.IsFavorite);
            Assert.Equal(isShared, account.IsShared);
        }
    }
}
