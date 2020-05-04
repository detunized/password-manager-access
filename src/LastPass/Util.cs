// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.LastPass
{
    internal static class Util
    {
        public static byte[] DeriveKey(string username, string password, int iterationCount)
        {
            if (iterationCount <= 0)
                throw new InternalErrorException("Iteration count should be positive");

            return iterationCount == 1
                ? Crypto.Sha256(username + password)
                : Pbkdf2.GenerateSha256(password.ToBytes(), username.ToBytes(), iterationCount, 32);
        }

        public static byte[] DeriveKeyHash(string username, string password, int iterationCount)
        {
            var key = DeriveKey(username, password, iterationCount);
            return iterationCount == 1
                ? Crypto.Sha256(key.ToHex() + password)
                : Pbkdf2.GenerateSha256(key, password.ToBytes(), 1, 32);
        }
    }
}
