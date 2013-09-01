using System;
using System.Security.Cryptography;

namespace LastPass
{
    static class FetcherHelper
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

            return Pbkdf2.Generate(password, username, iterationCount, 32);
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

            return Pbkdf2.Generate(key, password, 1, 32).ToHex();
        }
    }
}
