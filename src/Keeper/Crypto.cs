// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.Keeper
{
    using C = Common.Crypto;

    internal static class Crypto
    {
        public static byte[] HashPassword(string password, byte[] salt, int iterations)
        {
            return C.Sha256(C.Pbkdf2Sha256(password, salt, iterations, 32));
        }
    }
}
