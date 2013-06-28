using System;
using System.Security.Cryptography;
using System.Text;

namespace LastPass
{
    static class FetcherHelper
    {
        public static byte[] MakeKey(string username, string password, int iterationCount)
        {
            // TODO: Check for invalid interationCount

            if (iterationCount == 1)
            {
                using (var sha = new SHA256Managed())
                {
                    return sha.ComputeHash((username + password).ToBytes());
                }
            }

            using (var hmac = new HMACSHA256())
            {
                return new Pbkdf2(hmac, password, username, iterationCount).GetBytes(32);
            }
        }

        public static string MakeHash(string username, string password, int iterationCount)
        {
            // TODO: Check for invalid interationCount

            var key = MakeKey(username, password, iterationCount);
            if (iterationCount == 1)
            {
                using (var sha = new SHA256Managed())
                {
                    return ToHexString(sha.ComputeHash((ToHexString(key) + password).ToBytes()));
                }
            }

            using (var hmac = new HMACSHA256())
            {
                return ToHexString(new Pbkdf2(hmac, key, password, 1).GetBytes(32));
            }
        }

        public static string ToHexString(byte[] bytes)
        {
            return BitConverter.ToString(bytes).Replace("-", string.Empty).ToLower();
        }
    }
}
