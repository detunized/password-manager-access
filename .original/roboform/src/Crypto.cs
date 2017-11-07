// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Security.Cryptography;

namespace RoboForm
{
    internal static class Crypto
    {
        public static byte[] ComputeClientKey(string password, Client.AuthInfo authInfo)
        {
            return Hmac(HashPassword(password, authInfo), "Client Key".ToBytes());
        }

        public static byte[] Hmac(byte[] salt, byte[] message)
        {
            using (var hmac = new HMACSHA256 {Key = salt})
                return hmac.ComputeHash(message);
        }

        //
        // Internal
        //

        internal static byte[] HashPassword(string password, Client.AuthInfo authInfo)
        {
            var passwordBytes = password.ToBytes();
            if (authInfo.IsMd5)
                passwordBytes = Md5(passwordBytes);

            return Pbkdf2.Generate(passwordBytes, authInfo.Salt, authInfo.IterationCount, 32);
        }

        internal static byte[] Md5(byte[] data)
        {
            using (var md5 = MD5.Create())
                return md5.ComputeHash(data);
        }

        internal static byte[] Sha256(byte[] data)
        {
            using (var sha = new SHA256Managed())
                return sha.ComputeHash(data);
        }
    }
}
