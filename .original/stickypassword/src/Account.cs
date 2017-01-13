// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace StickyPassword
{
    public class Account
    {
        public Account(long id, string name, string url, string notes, Credentials[] credentials)
        {
            Id = id;
            Name = name;
            Url = url;
            Notes = notes;
            Credentials = credentials;
        }

        public long Id { get; private set; }
        public string Name { get; private set; }
        public string Url { get; private set; }
        public string Notes { get; private set; }
        public Credentials[] Credentials { get; private set; }
    }

    public class Credentials
    {
        public Credentials(string username, string password, string description)
        {
            Username = username;
            Password = password;
            Description = description;
        }

        public string Username { get; private set; }
        public string Password { get; private set; }
        public string Description { get; private set; }
    }
}
