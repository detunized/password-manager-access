// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.RoboForm
{
    internal static class Util
    {
        public static string RandomDeviceId()
        {
            // All the device ids returned by the server seem to be in this format.
            // Example: B57192ee77db5e5989c5ef7e091b119ea
            return "B" + Crypto.RandomBytes(16).ToHex();
        }

        public static byte[] ComputeClientKey(string password, AuthInfo authInfo)
        {
            return Crypto.HmacSha256(HashPassword(password, authInfo), "Client Key".ToBytes());
        }

        //
        // Internal
        //

        internal static byte[] HashPassword(string password, AuthInfo authInfo)
        {
            var passwordBytes = password.ToBytes();
            if (authInfo.IsMd5)
                passwordBytes = Crypto.Md5(passwordBytes);

            return Pbkdf2.GenerateSha256(passwordBytes, authInfo.Salt, authInfo.IterationCount, 32);
        }
    }
}
