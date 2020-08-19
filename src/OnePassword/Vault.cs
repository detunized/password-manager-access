// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable
namespace PasswordManagerAccess.OnePassword
{
    public class Vault
    {
        public VaultInfo Info { get; }
        public Account[] Accounts { get; }

        public Vault(VaultInfo info, Account[] accounts)
        {
            Info = info;
            Accounts = accounts;
        }
    }
}
