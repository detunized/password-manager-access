// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace OPVault
{
    public class Account
    {
        public readonly string Id;
        public readonly string Name;
        public readonly string Username;
        public readonly string Password;
        public readonly string Url;
        public readonly string Note;
        public readonly Folder Folder;

        public Account(string id,
                       string name,
                       string username,
                       string password,
                       string url,
                       string note,
                       Folder folder)
        {
            Id = id;
            Name = name;
            Username = username;
            Password = password;
            Url = url;
            Note = note;
            Folder = folder;
        }
    }
}
