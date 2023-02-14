// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.LastPass
{
    public class Account
    {
        public readonly string Id;
        public readonly string Name;
        public readonly string Username;
        public readonly string Password;
        public readonly string Url;
        public readonly string Path;
        public readonly string Notes;
        public readonly string Favorite;

        public Account(string id, string name, string username, string password, string url, string path, string notes, string favorite)
        {
            Id = id;
            Name = name;
            Username = username;
            Password = password;
            Url = url;
            Path = path;
            Notes = notes;
            Favorite= favorite;
        }
   }
}
