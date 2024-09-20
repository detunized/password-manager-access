// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.TrueKey
{
    public class EncryptedVault
    {
        public readonly byte[] MasterKeySalt;
        public readonly byte[] EncryptedMasterKey;
        public readonly EncryptedAccount[] EncryptedAccounts;

        public EncryptedVault(byte[] masterKeySalt, byte[] encryptedMasterKey, EncryptedAccount[] encryptedAccounts)
        {
            MasterKeySalt = masterKeySalt;
            EncryptedMasterKey = encryptedMasterKey;
            EncryptedAccounts = encryptedAccounts;
        }
    }
}
