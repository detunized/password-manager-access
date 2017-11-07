// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Security.Cryptography;

namespace RoboForm
{
    internal static class Crypto
    {
        public static byte[] HashPassword(string password, Client.AuthInfo authInfo)
        {
            var passwordBytes = password.ToBytes();
            if (authInfo.IsMd5)
                passwordBytes = Md5(passwordBytes);

            return Pbkdf2.Generate(passwordBytes, authInfo.Salt, authInfo.IterationCount, 32);
        }

        public static byte[] Md5(byte[] data)
        {
            using (var md5 = MD5.Create())
                return md5.ComputeHash(data);
        }

        public static byte[] Hmac(byte[] salt, byte[] message)
        {
            using (var hmac = new HMACSHA256 {Key = salt})
                return hmac.ComputeHash(message);
        }
    }
}
