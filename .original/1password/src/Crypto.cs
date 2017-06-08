// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Security.Cryptography;

namespace OnePassword
{
    internal static class Crypto
    {
        public static byte[] RandomBytes(int size)
        {
            using (var random = new RNGCryptoServiceProvider())
            {
                var bytes = new byte[size];
                random.GetBytes(bytes);
                return bytes;
            }
        }

        internal static byte[] Sha256(string message)
        {
            using (var sha = new SHA256Managed())
                return sha.ComputeHash(message.ToBytes());
        }
    }
}
