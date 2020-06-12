// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.OpVault
{
    public class Account
    {
        public string Id { get; }
        public string Name { get; }
        public string Username { get; }
        public string Password { get; }
        public string Url { get; }
        public string Note { get; }
        public Folder Folder { get; }

        //
        // Non-public
        //

        internal Account(string id,
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
