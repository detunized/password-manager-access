// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.StickyPassword;
using Xunit;

namespace PasswordManagerAccess.Test.StickyPassword
{
    public class AccountTest
    {
        [Fact]
        public void Account_properties_are_set()
        {
            var id = 0xdeadbeef;
            var name = "name";
            var url = "url";
            var notes = "notes";
            var credentials = new[]
            {
                new Credentials("username1", "password1", "description1"),
                new Credentials("username2", "password2", "description2"),
                new Credentials("username3", "password3", "description3"),
            };

            var account = new Account(id, name, url, notes, credentials);

            Assert.Equal(id, account.Id);
            Assert.Equal(name, account.Name);
            Assert.Equal(url, account.Url);
            Assert.Equal(notes, account.Notes);
            Assert.Equal(credentials, account.Credentials);
        }

        [Fact]
        public void Credentials_properties_are_set()
        {
            var username = "username";
            var password = "password";
            var description = "description";

            var credentials = new Credentials(username, password, description);

            Assert.Equal(username, credentials.Username);
            Assert.Equal(password, credentials.Password);
            Assert.Equal(description, credentials.Description);
        }
    }
}
