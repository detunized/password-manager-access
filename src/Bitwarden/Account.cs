// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.Bitwarden
{
    public class Account
    {
        public readonly string Id;
        public readonly string Name;
        public readonly string Username;
        public readonly string Password;
        public readonly string Url;
        public readonly string Note;
        public readonly string Totp;
        public readonly string DeletedDate;
        public readonly string Folder;

        public Account(string id,
                       string name,
                       string username,
                       string password,
                       string url,
                       string note,
                       string totp,
                       string deletedDate,
                       string folder)
        {
            Id = id;
            Name = name;
            Username = username;
            Password = password;
            Url = url;
            Note = note;
            Totp = totp;
            DeletedDate = deletedDate;
            Folder = folder;
        }
    }
}
