// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.ProtonPass
{
    internal static class Srp
    {
        internal static byte[] ParseModulus(string modulus)
        {
            const string startToken = "-----BEGIN PGP SIGNED MESSAGE-----";
            const string endToken = "-----BEGIN PGP SIGNATURE-----";

            var startIndex = modulus.IndexOf(startToken, StringComparison.Ordinal);
            var endIndex = modulus.IndexOf(endToken, StringComparison.Ordinal);
            if (startIndex == -1 || endIndex == -1 || endIndex <= startIndex)
                throw new InternalErrorException("Invalid PGP message format: missing start or end token");

            startIndex = modulus.IndexOf("\n\n", startIndex, endIndex - startIndex, StringComparison.Ordinal);
            if (startIndex == -1)
                throw new InternalErrorException("Invalid PGP message format: missing two blank lines before message");

            // Skip \n\n
            startIndex += 2;

            return modulus
                .Substring(startIndex, endIndex - startIndex)
                .Trim()
                .Decode64();
        }
    }
}
