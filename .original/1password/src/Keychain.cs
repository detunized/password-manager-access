// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;

namespace OnePassword
{
    internal class Keychain
    {
        public void Add(AesKey key)
        {
            _aes.Add(key.Id, key);
        }

        public void Add(RsaKey key)
        {
            _rsa.Add(key.Id, key);
        }

        public AesKey GetAes(string id)
        {
            if (!_aes.ContainsKey(id))
                throw new InvalidOperationException(string.Format("AES key '{0}' not found", id));

            return _aes[id];
        }

        public RsaKey GetRsa(string id)
        {
            if (!_rsa.ContainsKey(id))
                throw new InvalidOperationException(string.Format("RSA key '{0}' not found", id));

            return _rsa[id];
        }

        public byte[] Decrypt(Encrypted encrypted)
        {
            switch (encrypted.Scheme)
            {
            case AesKey.EncryptionScheme:
                return GetAes(encrypted.KeyId).Decrypt(encrypted);
            case RsaKey.EncryptionScheme:
                return GetRsa(encrypted.KeyId).Decrypt(encrypted);
            }

            throw new InvalidOperationException(string.Format("Unsupported encryption scheme '{0}'",
                                                              encrypted.Scheme));
        }

        private readonly Dictionary<string, AesKey> _aes = new Dictionary<string, AesKey>();
        private readonly Dictionary<string, RsaKey> _rsa = new Dictionary<string, RsaKey>();
    }
}
