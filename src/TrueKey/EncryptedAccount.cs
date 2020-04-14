// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace TrueKey
{
    public class EncryptedAccount
    {
        public readonly int Id;
        public readonly string Name;
        public readonly string Username;
        public readonly byte[] EncryptedPassword;
        public readonly string Url;
        public readonly byte[] EncryptedNote;

        public EncryptedAccount(int id, string name, string username, byte[] encryptedPassword, string url, byte[] encryptedNote)
        {
            Id = id;
            Name = name;
            Username = username;
            EncryptedPassword = encryptedPassword;
            Url = url;
            EncryptedNote = encryptedNote;
        }
    }
}
