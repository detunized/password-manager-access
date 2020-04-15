// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using NUnit.Framework;

namespace TrueKey.Test
{
    [TestFixture]
    class EncryptedAccountTest
    {
        [Test]
        public void EncryptedAccount_properties_are_set()
        {
            var id = 1337;
            var name = "name";
            var username = "username";
            var password = "password".ToBytes();
            var url = "url";
            var note = "note".ToBytes();
            var account = new EncryptedAccount(id, name, username, password, url, note);

            Assert.That(account.Id, Is.EqualTo(id));
            Assert.That(account.Name, Is.EqualTo(name));
            Assert.That(account.Username, Is.EqualTo(username));
            Assert.That(account.EncryptedPassword, Is.EqualTo(password));
            Assert.That(account.Url, Is.EqualTo(url));
            Assert.That(account.EncryptedNote, Is.EqualTo(note));
        }
    }
}
