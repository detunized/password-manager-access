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

        public AesKey GetAes(string id)
        {
            return _aes[id];
        }

        public byte[] Decrypt(Encrypted encrypted)
        {
            if (!_aes.ContainsKey(encrypted.KeyId))
                throw new InvalidOperationException(string.Format("Key '{0}' not found", encrypted.KeyId));

            return _aes[encrypted.KeyId].Decrypt(encrypted);
        }

        private readonly Dictionary<string, AesKey> _aes = new Dictionary<string, AesKey>();
    }
}
