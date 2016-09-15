// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Linq;
using System.Security.Cryptography;

namespace ZohoVault
{
    public static class Crypto
    {
        public static byte[] Decrypt(byte[] ctrCiphertext, byte[] key)
        {
            throw new NotImplementedException();
        }

        internal static byte[] ComputeAesCtrKey(byte[] key)
        {
            using (
                var aes = new AesManaged
                {
                    BlockSize = 128,
                    KeySize = 256,
                    Key = key,
                    Mode = CipherMode.ECB,
                    Padding = PaddingMode.None
                })
            {
                var encryptor = aes.CreateEncryptor();
                var ctrKey = encryptor.TransformFinalBlock(key, 0, 16);

                return ctrKey.Concat(ctrKey).ToArray();
            }
        }
    }
}
