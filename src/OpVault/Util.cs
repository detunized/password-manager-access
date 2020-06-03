// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.OpVault
{
    internal static class Util
    {
        public static KeyMac DeriveKek(byte[] password, byte[] salt, int iterations)
        {
            return new KeyMac(Pbkdf2.GenerateSha512(password, salt, iterations, 64));
        }

        public static byte[] DecryptAes(byte[] ciphertext, byte[] iv, KeyMac key)
        {
            return Crypto.DecryptAes256CbcNoPadding(ciphertext, iv, key.Key);
        }
    }
}
