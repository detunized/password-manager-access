// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Security.Cryptography;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.LastPass
{
    internal static class FetcherHelper
    {
        public static byte[] MakeKey(string username, string password, int iterationCount)
        {
            if (iterationCount <= 0)
                throw new ArgumentOutOfRangeException("iterationCount", "Iteration count should be positive");

            if (iterationCount == 1)
            {
                using (var sha = new SHA256Managed())
                {
                    return sha.ComputeHash((username + password).ToBytes());
                }
            }

            return Pbkdf2.GenerateSha256(password.ToBytes(), username.ToBytes(), iterationCount, 32);
        }

        public static string MakeHash(string username, string password, int iterationCount)
        {
            if (iterationCount <= 0)
                throw new ArgumentOutOfRangeException("iterationCount", "Iteration count should be positive");

            var key = MakeKey(username, password, iterationCount);
            if (iterationCount == 1)
            {
                using (var sha = new SHA256Managed())
                {
                    return sha.ComputeHash((key.ToHex() + password).ToBytes()).ToHex();
                }
            }

            return Pbkdf2.GenerateSha256(key, password.ToBytes(), 1, 32).ToHex();
        }
    }
}
