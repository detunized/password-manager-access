// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.OnePassword
{
    internal class AesKey: IDecryptor
    {
        public const string ContainerType = "b5+jwk+json";
        public const string EncryptionScheme = "A256GCM";

        public readonly string Id;
        public readonly byte[] Key;

        public static AesKey Parse(Response.AesKey json)
        {
            return new AesKey(json.Id, json.Key.Decode64Loose());
        }

        public AesKey(string id, byte[] key)
        {
            Id = id;
            Key = key;
        }

        public Encrypted Encrypt(byte[] plaintext)
        {
            return Encrypt(plaintext, Crypto.RandomBytes(12));
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
                throw new InternalErrorException("Mismatching key id");

            if (e.Scheme != EncryptionScheme)
                throw new InternalErrorException(
                    $"Invalid encryption scheme '{e.Scheme}', expected '{EncryptionScheme}'");

            return AesGcm.Decrypt(Key, e.Ciphertext, e.Iv, new byte[0]);
        }
    }
}
