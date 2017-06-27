// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace OnePassword
{
    internal class Encrypted
    {
        public readonly string KeyId;
        public readonly string Scheme;
        public readonly string Container;
        public readonly byte[] Iv;
        public readonly byte[] Ciphertext;

        public Encrypted(string keyId, string scheme, string container, byte[] iv, byte[] ciphertext)
        {
            KeyId = keyId;
            Scheme = scheme;
            Container = container;
            Iv = iv;
            Ciphertext = ciphertext;
        }
    }
}
