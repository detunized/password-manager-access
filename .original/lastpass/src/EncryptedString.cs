// Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;

namespace LastPass
{
    public class EncryptedString
    {
        public EncryptedString(byte[] encrypted)
        {
            _encrypted = encrypted;
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
                    throw new InvalidOperationException("The field has not been decrypted yet");

                return _decrypted;
            }
        }

        private readonly byte[] _encrypted;
        private string _decrypted;
    }
}