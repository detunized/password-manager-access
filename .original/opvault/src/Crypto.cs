// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace OPVault
{
    internal static class Crypto
    {
        public static KeyMac DeriveKek(byte[] password, byte[] salt, int iterations)
        {
            return new KeyMac(Pbkdf2.GenerateSha512(password, salt, iterations, 64));
        }
    }
}
