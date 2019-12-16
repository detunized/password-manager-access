// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.OnePassword;
using Xunit;

namespace PasswordManagerAccess.Test.OnePassword
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
            var mainUrl = "main-url";
            var note = "note";
            var urls = new Account.Url[] { new Account.Url("url1", "http://url1"),
                                           new Account.Url("url2", "http://url2") };
            var fields = new Account.Field[] { new Account.Field("f1", "n1", "s1"),
                                               new Account.Field("f2", "n2", "s2") };
            var account = new Account(id, name, username, password, mainUrl, note, urls, fields);

            Assert.Equal(id, account.Id);
            Assert.Equal(name, account.Name);
            Assert.Equal(username, account.Username);
            Assert.Equal(password, account.Password);
            Assert.Equal(mainUrl, account.MainUrl);
            Assert.Equal(note, account.Note);
            Assert.Equal(urls, account.Urls);
            Assert.Equal(fields, account.Fields);
        }
    }
}
