// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;
using PasswordManagerAccess.ZohoVault.Ui;

namespace PasswordManagerAccess.ZohoVault
{
    public class Vault
    {
        public readonly Account[] Accounts;

        public static Vault Open(Credentials credentials, Settings settings, IUi ui, ISecureStorage storage)
        {
            using var transport = new RestTransport();
            return Open(credentials, settings, ui, storage, transport);
        }

        //
        // Internal
        //

        internal static Vault Open(Credentials credentials, Settings settings, IUi ui, ISecureStorage storage, IRestTransport transport)
        {
            return new Vault(Client.OpenVault(credentials, settings, ui, storage, transport));
        }

        internal Vault(Account[] accounts)
        {
            Accounts = accounts;
        }
    }
}
