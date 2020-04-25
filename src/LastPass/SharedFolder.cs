// Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace LastPass
{
    public class SharedFolder
    {
        public SharedFolder(string id, string name, byte[] encryptionKey)
        {
            Id = id;
            Name = name;
            EncryptionKey = encryptionKey;
        }

        public string Id { get; private set; }
        public string Name { get; private set; }
        public byte[] EncryptionKey { get; private set; }
    }
}
