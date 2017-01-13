// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace StickyPassword
{
    public struct Account
    {
        public readonly long Id;
        public readonly string Name;
        public readonly string Url;
        public readonly string Notes;
        public readonly Credentials[] Credentials;

        public Account(long id, string name, string url, string notes, Credentials[] credentials)
        {
            Id = id;
            Name = name;
            Url = url;
            Notes = notes;
            Credentials = credentials;
        }
    }

    public struct Credentials
    {
        public readonly string Username;
        public readonly string Password;
        public readonly string Description;

        public Credentials(string username, string password, string description)
        {
            Username = username;
            Password = password;
            Description = description;
        }
    }
}
