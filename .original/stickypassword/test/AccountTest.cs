// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using NUnit.Framework;

namespace StickyPassword.Test
{
    [TestFixture]
    class AccountTest
    {
        [Test]
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

            Assert.That(account.Id, Is.EqualTo(id));
            Assert.That(account.Name, Is.EqualTo(name));
            Assert.That(account.Url, Is.EqualTo(url));
            Assert.That(account.Notes, Is.EqualTo(notes));
            Assert.That(account.Credentials, Is.EqualTo(credentials));
        }

        [Test]
        public void Credentials_properties_are_set()
        {
            var username = "username";
            var password = "password";
            var description = "description";

            var credentials = new Credentials(username, password, description);

            Assert.That(credentials.Username, Is.EqualTo(username));
            Assert.That(credentials.Password, Is.EqualTo(password));
            Assert.That(credentials.Description, Is.EqualTo(description));
        }
    }
}
