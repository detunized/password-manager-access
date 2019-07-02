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
            using (var rest = new RestClient())
                return Open(username, password, passphrase, ui, rest);
        }

        //
        // Private
        //

        private static Vault Open(string username, string password, string passphrase, Ui ui, RestClient rest)
        {
            return new Vault(Client.OpenVault(username, password, passphrase, ui, rest));
        }

        private Vault(Account[] accounts)
        {
            Accounts = accounts;
        }
    }
}
