// Copyright (C) 2015 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordBox
{
    static class Crypto
    {
        public static byte[] Decrypt(string encryptedBase64, string keyHex)
        {
            if (encryptedBase64.Length == 0)
                return new byte[0];

            return "".ToBytes();
        }
    }
}
