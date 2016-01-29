// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Security.Cryptography;

namespace Dashlane
{
    static class Parser
    {
        public static byte[] ComputeEncryptionKey(string password, byte[] salt)
        {
            return new Rfc2898DeriveBytes(password, salt, 10204).GetBytes(32);
        }

        public static byte[] Sha1(byte[] bytes, int times)
        {
            var result = bytes;
            using (var sha = new SHA1Managed())
                for (var i = 0; i < times; ++i)
                    result = sha.ComputeHash(result);

            return result;
        }
    }
}
