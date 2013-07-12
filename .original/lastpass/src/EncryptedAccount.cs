using System;

namespace LastPass
{
    public struct EncryptedString
    {
        public EncryptedString(byte[] encrypted)
        {
            _encrypted = encrypted;
            _decrypted = null;
        }

        public string Decrypt(byte[] encryptionKey)
        {
            if (_decrypted == null)
                _decrypted = ParserHelper.DecryptAes256(_encrypted, encryptionKey);

            return _decrypted;
        }

        public static implicit operator string(EncryptedString self)
        {
            return self.Decrypted;
        }

        public byte[] Encrypted
        {
            get
            {
                return _encrypted;
            }
        }

        public string Decrypted
        {
            get
            {
                if (_decrypted == null)
                    throw new InvalidOperationException("The field has not been decrypted yet.");

                return _decrypted;
            }
        }

        private readonly byte[] _encrypted;
        private string _decrypted;
    }

    public class EncryptedAccount
    {
        public EncryptedAccount(string id, byte[] name, byte[] username, byte[] password, string url, byte[] group)
        {
            Id = id;
            Name = new EncryptedString(name);
            Username = new EncryptedString(username);
            Password = new EncryptedString(password);
            Url = url;
            Group = new EncryptedString(group);
        }

        public string Id { get; private set; }
        public EncryptedString Name { get; private set; }
        public EncryptedString Username { get; private set; }
        public EncryptedString Password { get; private set; }
        public string Url { get; private set; }
        public EncryptedString Group { get; private set; }
    }
}