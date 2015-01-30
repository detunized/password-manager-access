// Copyright (C) 2015 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordBox
{
    public class Account
    {
        public Account(string id, string name, string username, string password, string url, string notes)
        {
            Id = id;
            Name = name;
            Username = username;
            Password = password;
            Url = url;
            Notes = notes;
        }

        public string Id { get; private set; }
        public string Name { get; private set; }
        public string Username { get; private set; }
        public string Password { get; private set; }
        public string Url { get; private set; }
        public string Notes { get; private set; }
    }
}
