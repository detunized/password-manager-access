// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;
using PasswordManagerAccess.TrueKey;
using Xunit;

namespace PasswordManagerAccess.Test.TrueKey
{
    public class EncryptedAccountTest
    {
        [Fact]
        public void EncryptedAccount_properties_are_set()
        {
            var id = 1337;
            var name = "name";
            var username = "username";
            var password = "password".ToBytes();
            var url = "url";
            var note = "note".ToBytes();
            var account = new EncryptedAccount(id, name, username, password, url, note);

            Assert.Equal(id, account.Id);
            Assert.Equal(name, account.Name);
            Assert.Equal(username, account.Username);
            Assert.Equal(password, account.EncryptedPassword);
            Assert.Equal(url, account.Url);
            Assert.Equal(note, account.EncryptedNote);
        }
    }
}
