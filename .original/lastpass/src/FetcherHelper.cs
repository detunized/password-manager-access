using System;
using System.Security.Cryptography;
using System.Text;

namespace LastPass
{
    static class FetcherHelper
    {
        public static byte[] MakeKey(string username, string password, int iterationCount)
        {
            if (iterationCount == 1)
            {
                using (var sha = SHA256.Create())
                {
                    return sha.ComputeHash(UTF8Encoding.UTF8.GetBytes(username + password));
                }
            }

            throw new NotImplementedException();
        }
    }
}
