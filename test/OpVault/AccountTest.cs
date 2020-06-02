// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using NUnit.Framework;

namespace OPVault.Test
{
    [TestFixture]
    class AccountTest
    {
        [Test]
        public void Account_properties_are_set()
        {
            var id = "id";
            var name = "name";
            var username = "username";
            var password = "password";
            var url = "url";
            var note = "note";
            var folder = new Folder("id", "name");
            var account = new Account(id, name, username, password, url, note, folder);

            Assert.That(account.Id, Is.EqualTo(id));
            Assert.That(account.Name, Is.EqualTo(name));
            Assert.That(account.Username, Is.EqualTo(username));
            Assert.That(account.Password, Is.EqualTo(password));
            Assert.That(account.Url, Is.EqualTo(url));
            Assert.That(account.Note, Is.EqualTo(note));
            Assert.That(account.Folder, Is.SameAs(folder));
        }
    }
}
