// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Linq;
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

        // This is a clean reimplementation of https://tools.ietf.org/html/rfc5869
        // No strangely licensed code was used here even as a reference.
        public static byte[] Hkdf(byte[] ikm, byte[] salt, byte[] info, int byteCount)
        {
            // TODO: See if we need to parametrize on HMAC

            byte[] prk;
            using (var hmac = new HMACSHA256(salt))
                prk = hmac.ComputeHash(ikm);

            using (var hmac = new HMACSHA256(prk))
            {
                // TODO: This could be made more efficient by at least not joining
                //       arrays left and right. A good start would be to preallocate
                //       the result and copy parts into it.
                var result = new byte[0];
                var current = new byte[0];
                var counter = new byte[1];

                while (result.Length < byteCount)
                {
                    ++counter[0];
                    current = hmac.ComputeHash(current.Concat(info).Concat(counter).ToArray());
                    result = result.Concat(current).ToArray();
                }

                return result.Take(byteCount).ToArray();
            }
        }
    }
}
