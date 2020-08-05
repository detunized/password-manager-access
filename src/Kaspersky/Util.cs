// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Text;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Kaspersky
{
    internal class Util
    {
        internal static byte[] DeriveMasterPasswordAuthKey(string userId,
                                                           byte[] encryptionKey,
                                                           DatabaseInfo databaseInfo)
        {
            return Pbkdf2.GenerateSha256(password: encryptionKey,
                                         salt: Encoding.Unicode.GetBytes(userId),
                                         iterationCount: 1500,
                                         byteCount: 64);
        }

        internal static byte[] DeriveEncryptionKey(string password, DatabaseInfo databaseInfo)
        {
            return Crypto.Pbkdf2Sha256(password: password,
                                       salt: databaseInfo.Salt,
                                       iterations: databaseInfo.Iterations,
                                       byteCount: 32);
        }
    }
}
