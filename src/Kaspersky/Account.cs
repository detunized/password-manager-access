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
        public readonly string Folder;
        public Credentials[] Credentials { get; internal set; }

        public Account(string id, string name, string url, string notes, string folder, Credentials[] credentials)
        {
            Id = id;
            Name = name;
            Url = url;
            Notes = notes;
            Folder = folder;
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
