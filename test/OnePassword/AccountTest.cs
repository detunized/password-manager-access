// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using NUnit.Framework;

namespace OnePassword.Test
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
            var mainUrl = "main-url";
            var note = "note";
            var urls = new Account.Url[] { new Account.Url("url1", "http://url1"),
                                           new Account.Url("url2", "http://url2") };
            var fields = new Account.Field[] { new Account.Field("f1", "n1", "s1"),
                                               new Account.Field("f2", "n2", "s2") };
            var account = new Account(id, name, username, password, mainUrl, note, urls, fields);

            Assert.That(account.Id, Is.EqualTo(id));
            Assert.That(account.Name, Is.EqualTo(name));
            Assert.That(account.Username, Is.EqualTo(username));
            Assert.That(account.Password, Is.EqualTo(password));
            Assert.That(account.MainUrl, Is.EqualTo(mainUrl));
            Assert.That(account.Note, Is.EqualTo(note));
            Assert.That(account.Urls, Is.EquivalentTo(urls));
            Assert.That(account.Fields, Is.EquivalentTo(fields));
        }
    }
}
