// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System;
using System.Linq;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.ProtonPass
{
    internal static class Srp
    {
        internal static byte[] ParseModulus(string message)
        {
            const string startToken = "-----BEGIN PGP SIGNED MESSAGE-----";
            const string endToken = "-----BEGIN PGP SIGNATURE-----";

            var startIndex = message.IndexOf(startToken, StringComparison.Ordinal);
            var endIndex = message.IndexOf(endToken, StringComparison.Ordinal);
            if (startIndex == -1 || endIndex == -1 || endIndex <= startIndex)
                throw new InternalErrorException("Invalid PGP message format: missing start or end token");

            startIndex = message.IndexOf("\n\n", startIndex, endIndex - startIndex, StringComparison.Ordinal);
            if (startIndex == -1)
                throw new InternalErrorException("Invalid PGP message format: missing two blank lines before message");

            // Skip \n\n
            startIndex += 2;

            return message
                .Substring(startIndex, endIndex - startIndex)
                .Trim()
                .Decode64();
        }

        internal static byte[] HashPassword(string password, byte[] salt, byte[] modulus)
        {
            var bcryptSalt = "$2y$10$" + EncodeBase64(salt.Concat("proton".ToBytes()).ToArray(), 16);
            return ExpandHash(BCrypt.Net.BCrypt.HashPassword(password, bcryptSalt).ToBytes().Concat(modulus).ToArray());
        }

        internal static byte[] ExpandHash(byte[] hash)
        {
            var expanded = new byte[64 * 4];

            var toHash = new byte[hash.Length + 1];
            hash.CopyTo(toHash, 0);

            for (var i = 0; i < 4; i++)
            {
                toHash[toHash.Length - 1] = (byte)i;
                Crypto.Sha512(toHash).CopyTo(expanded, i * 64);
            }

            return expanded;
        }

        // TODO: Move to Common
        // This code is adapted from https://github.com/BcryptNet/bcrypt.net/blob/main/src/BCrypt.Net/BCrypt.cs
        internal static string EncodeBase64(byte[] byteArray, int length)
        {
            if (length <= 0 || length > byteArray.Length)
                throw new ArgumentException("Invalid length", nameof(length));

            var encodedSize = (length * 4 + 2) / 3;
            var encoded = new char[encodedSize];

            var pos = 0;
            var off = 0;
            while (off < length)
            {
                var c1 = byteArray[off++] & 0xff;
                encoded[pos++] = Base64Code[(c1 >> 2) & 0x3f];
                c1 = (c1 & 0x03) << 4;
                if (off >= length)
                {
                    encoded[pos++] = Base64Code[c1 & 0x3f];
                    break;
                }

                var c2 = byteArray[off++] & 0xff;
                c1 |= (c2 >> 4) & 0x0f;
                encoded[pos++] = Base64Code[c1 & 0x3f];
                c1 = (c2 & 0x0f) << 2;
                if (off >= length)
                {
                    encoded[pos++] = Base64Code[c1 & 0x3f];
                    break;
                }

                c2 = byteArray[off++] & 0xff;
                c1 |= (c2 >> 6) & 0x03;
                encoded[pos++] = Base64Code[c1 & 0x3f];
                encoded[pos++] = Base64Code[c2 & 0x3f];
            }

            return new string(encoded);
        }

        private static readonly char[] Base64Code =
        {
            '.', '/', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
            'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',
            'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
            'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
        };
    }
}
