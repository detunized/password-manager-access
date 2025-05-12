// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Security.Cryptography;

namespace PasswordManagerAccess.Common
{
    // This is only needed for Mono and some outdated versions of .NET.
    // The current .NET Core and .NET Framework support configurable hash
    // algorithm in PBKDF2. Remove this when no longer needed.
    internal static class Pbkdf2
    {
        public static byte[] GenerateSha1(byte[] password, byte[] salt, int iterationCount, int byteCount) =>
            Generate(password, salt, iterationCount, byteCount, HashAlgorithmName.SHA1);

        public static byte[] GenerateSha256(byte[] password, byte[] salt, int iterationCount, int byteCount) =>
            Generate(password, salt, iterationCount, byteCount, HashAlgorithmName.SHA256);

        public static byte[] GenerateSha512(byte[] password, byte[] salt, int iterationCount, int byteCount) =>
            Generate(password, salt, iterationCount, byteCount, HashAlgorithmName.SHA512);

        internal static byte[] Generate(byte[] password, byte[] salt, int iterationCount, int byteCount, HashAlgorithmName hashAlgorithmName)
        {
            if (iterationCount <= 0)
                throw new InternalErrorException("Iteration count should be positive");

            if (byteCount < 0)
                throw new InternalErrorException("Byte count should be nonnegative");

            if (byteCount == 0)
                return [];

            return new Rfc2898DeriveBytes(password, salt, iterationCount, hashAlgorithmName).GetBytes(byteCount);
        }
    }
}
