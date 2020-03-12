// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Linq;
using System.Security.Cryptography;

namespace PasswordManagerAccess.Common
{
    // This is a clean reimplementation of https://tools.ietf.org/html/rfc5869
    // No strangely licensed code has been used here even as a reference.
    internal static class Hkdf
    {
        // TODO: See if we need to parametrize on HMAC, currently it's SHA-256 only
        public static byte[] Generate(byte[] ikm, byte[] salt, byte[] info, int byteCount)
        {
            var saltHmac = new HMACSHA256(salt);
            var prk = saltHmac.ComputeHash(ikm);

            // TODO: @performance
            // TODO: This could be made more efficient by at least not joining
            //       arrays left and right. A good start would be to preallocate
            //       the result and copy parts into it.
            using var prkHmac = new HMACSHA256(prk);
            var result = new byte[0];
            var current = new byte[0];
            var counter = new byte[1];

            while (result.Length < byteCount)
            {
                ++counter[0];
                current = prkHmac.ComputeHash(current.Concat(info).Concat(counter).ToArray());
                result = result.Concat(current).ToArray();
            }

            return result.Take(byteCount).ToArray();
        }
    }
}
