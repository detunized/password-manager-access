// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;

namespace OnePassword
{
    internal class AesKey
    {
        public const string ContainerType = "b5+jwk+json";
        public const string EncryptionScheme = "A256GCM";

        public readonly string Id;
        public readonly byte[] Key;

        public AesKey(string id, byte[] key)
        {
            Id = id;
            Key = key;
        }

        public Encrypted Encrypt(byte[] plaintext, byte[] iv)
        {
            return new Encrypted(keyId: Id,
                                 scheme: EncryptionScheme,
                                 container: ContainerType,
                                 iv: iv,
                                 ciphertext: AesGcm.Encrypt(Key, plaintext, iv, new byte[0]));
        }

        public byte[] Decrypt(Encrypted e)
        {
            if (e.KeyId != Id)
                throw new InvalidOperationException("Mismatching key id");

            if (e.Scheme != EncryptionScheme)
                throw new InvalidOperationException(
                    string.Format("Invalid encryption scheme '{0}', expected '{1}'",
                                  e.Scheme,
                                  EncryptionScheme));

            return AesGcm.Decrypt(Key, e.Ciphertext, e.Iv, new byte[0]);
        }
    }
}
