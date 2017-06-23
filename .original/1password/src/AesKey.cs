// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

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

        public byte[] Encrypt(byte[] plaintext, byte[] iv)
        {
            return AesGcm.Encrypt(Key, plaintext, iv, new byte[0]);
        }

        public byte[] Decrypt(byte[] ciphertext, byte[] iv)
        {
            return AesGcm.Decrypt(Key, ciphertext, iv, new byte[0]);
        }
    }
}
