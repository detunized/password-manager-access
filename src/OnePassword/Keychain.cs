// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.OnePassword
{
    internal class Keychain: IDecryptor
    {
        public void Add(AesKey key)
        {
            _aes[key.Id] = key;
        }

        public void Add(RsaKey key)
        {
            _rsa[key.Id] = key;
        }

        public AesKey GetAes(string id)
        {
            if (!_aes.ContainsKey(id))
                throw new InternalErrorException($"AES key '{id}' not found");

            return _aes[id];
        }

        public RsaKey GetRsa(string id)
        {
            if (!_rsa.ContainsKey(id))
                throw new InternalErrorException($"RSA key '{id}' not found");

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

            throw new UnsupportedFeatureException($"Encryption scheme '{encrypted.Scheme}' is not supported");
        }

        private readonly Dictionary<string, AesKey> _aes = new Dictionary<string, AesKey>();
        private readonly Dictionary<string, RsaKey> _rsa = new Dictionary<string, RsaKey>();
    }
}
