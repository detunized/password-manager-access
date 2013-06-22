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
                using (var sha = SHA256.Create())
                {
                    return sha.ComputeHash(UTF8Encoding.UTF8.GetBytes(username + password));
                }
            }
            else
            {
                using (var hmac = new HMACSHA256())
                {
                    return new PBKDF2(hmac, password, username, iterationCount).GetBytes(32);
                }
            }
        }
    }
}
