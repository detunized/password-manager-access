// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Linq;
using PasswordManagerAccess.Common;
using R = PasswordManagerAccess.OnePassword.Response;

namespace PasswordManagerAccess.OnePassword
{
    internal class Keychain : IDecryptor
    {
        public Keychain(params AesKey[] aesKeys)
        {
            foreach (var key in aesKeys)
                _aes[key.Id] = key;
        }

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
            if (_aes.TryGetValue(id, out var aes))
                return aes;

            throw new InternalErrorException($"AES key '{id}' not found");
        }

        public RsaKey GetRsa(string id)
        {
            if (_rsa.TryGetValue(id, out var rsa))
                return rsa;

            throw new InternalErrorException($"RSA key '{id}' not found");
        }

        public bool CanDecrypt(Encrypted encrypted) => CanDecrypt(encrypted.Scheme, encrypted.KeyId);

        public bool CanDecrypt(R.Encrypted encrypted) => CanDecrypt(encrypted.Scheme, encrypted.KeyId);

        public byte[] Decrypt(Encrypted encrypted)
        {
            if (encrypted.Scheme == AesKey.EncryptionScheme)
                return GetAes(encrypted.KeyId).Decrypt(encrypted);

            if (RsaKey.EncryptionSchemes.Contains(encrypted.Scheme))
                return GetRsa(encrypted.KeyId).Decrypt(encrypted);

            throw new UnsupportedFeatureException($"Encryption scheme '{encrypted.Scheme}' is not supported");
        }

        //
        // Internal
        //

        internal bool CanDecrypt(string scheme, string keyId)
        {
            if (scheme == AesKey.EncryptionScheme)
                return _aes.ContainsKey(keyId);

            if (RsaKey.EncryptionSchemes.Contains(scheme))
                return _rsa.ContainsKey(keyId);

            throw new UnsupportedFeatureException($"Encryption scheme '{scheme}' is not supported");
        }

        //
        // Private
        //

        private readonly Dictionary<string, AesKey> _aes = new();
        private readonly Dictionary<string, RsaKey> _rsa = new();
    }
}
