// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Security.Cryptography;

namespace StickyPassword
{
    static class Crypto
    {
        public static byte[] DeriveTokenKey(string username, string password)
        {
            var salt = Md5(username.ToLower());
            var kdf = new Rfc2898DeriveBytes(password, salt, 5000);
            return kdf.GetBytes(32);
        }

        public static byte[] Md5(string text)
        {
            using (var md5 = MD5.Create())
                return md5.ComputeHash(text.ToBytes());
        }
    }
}
