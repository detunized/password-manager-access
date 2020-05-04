// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.LastPass
{
    internal class SharedFolder
    {
        public readonly string Id;
        public readonly string Name;
        public readonly byte[] EncryptionKey;

        public SharedFolder(string id, string name, byte[] encryptionKey)
        {
            Id = id;
            Name = name;
            EncryptionKey = encryptionKey;
        }
    }
}
