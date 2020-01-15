// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.ZohoVault
{
    public class Vault
    {
        public readonly Account[] Accounts;

        public static Vault Open(string username, string password, string passphrase, Ui ui)
        {
            using (var transport = new RestTransport())
                return Open(username, password, passphrase, ui, transport);
        }

        //
        // Internal
        //

        internal static Vault Open(string username,
                                   string password,
                                   string passphrase,
                                   Ui ui,
                                   IRestTransport transport)
        {
            return new Vault(Client.OpenVault(username, password, passphrase, ui, transport));
        }

        internal Vault(Account[] accounts)
        {
            Accounts = accounts;
        }
    }
}
