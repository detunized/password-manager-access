// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.ZohoVault
{
    public class Vault
    {
        public readonly Account[] Accounts;

        public static Vault Open(string username, string password, string passphrase, Ui ui, ISecureStorage storage)
        {
            using var transport = new RestTransport();
            return Open(username, password, passphrase, ui, storage, transport);
        }

        //
        // Internal
        //

        internal static Vault Open(string username,
                                   string password,
                                   string passphrase,
                                   Ui ui,
                                   ISecureStorage storage,
                                   IRestTransport transport)
        {
            return new Vault(Client.OpenVault(username, password, passphrase, ui, storage, transport));
        }

        internal Vault(Account[] accounts)
        {
            Accounts = accounts;
        }
    }
}
