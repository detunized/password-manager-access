// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.Kaspersky
{
    public class Account
    {
        public readonly string Id;
        public readonly string Name;
        public readonly string Url;
        public readonly string Notes;
        public Credentials[] Credentials { get; internal set; }

        public Account(string id, string name, string url, string notes, Credentials[] credentials)
        {
            Id = id;
            Name = name;
            Url = url;
            Notes = notes;
            Credentials = credentials;
        }
    }

    public class Credentials
    {
        public readonly string Id;
        public readonly string Name;
        public readonly string Username;
        public readonly string Password;
        public readonly string Notes;

        public Credentials(string id, string name, string username, string password, string notes)
        {
            Id = id;
            Name = name;
            Username = username;
            Password = password;
            Notes = notes;
        }
    }
}
