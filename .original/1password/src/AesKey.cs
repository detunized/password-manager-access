// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using Newtonsoft.Json.Linq;

namespace OnePassword
{
    internal class AesKey
    {
        public const string ContainerType = "b5+jwk+json";
        public const string EncryptionScheme = "A256GCM";

        public readonly string Id;
        public readonly byte[] Key;

        public static AesKey Parse(JToken json)
        {
            return new AesKey(id: json.StringAt("kid"),
                              key: json.StringAt("k").Decode64());
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
                throw ExceptionFactory.MakeInvalidOperation("AES key: mismatching key id");

            if (e.Scheme != EncryptionScheme)
                throw ExceptionFactory.MakeInvalidOperation(
                    string.Format("AES key: invalid encryption scheme '{0}', expected '{1}'",
                                  e.Scheme,
                                  EncryptionScheme));

            return AesGcm.Decrypt(Key, e.Ciphertext, e.Iv, new byte[0]);
        }
    }
}
