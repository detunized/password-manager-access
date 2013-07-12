using System;

namespace LastPass
{
    public class EncryptedAccount
    {
        [Flags]
        public enum Field
        {
            Name = 1,
            Username = 2,
            Password = 4,
            Group = 8,
        }

        public EncryptedAccount(string id, byte[] name, byte[] username, byte[] password, string url, byte[] group)
        {
            Id = id;
            Name = new EncryptedString(name);
            Username = new EncryptedString(username);
            Password = new EncryptedString(password);
            Url = url;
            Group = new EncryptedString(group);
        }

        public void Decrypt(Field fields, byte[] encryptionKey)
        {
            if ((fields & Field.Name) != 0)
            {
                Name.Decrypt(encryptionKey);
            }

            if ((fields & Field.Username) != 0)
            {
                Username.Decrypt(encryptionKey);
            }

            if ((fields & Field.Password) != 0)
            {
                Password.Decrypt(encryptionKey);
            }

            if ((fields & Field.Group) != 0)
            {
                Group.Decrypt(encryptionKey);
            }
        }

        public string Id { get; private set; }
        public EncryptedString Name { get; private set; }
        public EncryptedString Username { get; private set; }
        public EncryptedString Password { get; private set; }
        public string Url { get; private set; }
        public EncryptedString Group { get; private set; }
    }
}