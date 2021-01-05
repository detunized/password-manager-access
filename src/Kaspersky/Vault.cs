// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Kaspersky
{
    public class Vault
    {
        public readonly Account[] Accounts;

        public static Vault Open(string username, string accountPassword, string vaultPassword)
        {
            using var restTransport = new RestTransport();
            using var boshTransport = new WebSocketBoshTransport();
            return Open(username, accountPassword, vaultPassword, restTransport, boshTransport);
        }

        //
        // Internal
        //

        internal static Vault Open(string username,
                                   string accountPassword,
                                   string vaultPassword,
                                   IRestTransport restTransport,
                                   IBoshTransport boshTransport)
        {
            return new Vault(Client.OpenVault(username, accountPassword, vaultPassword, restTransport, boshTransport));
        }

        //
        // Private
        //

        private Vault(Account[] accounts)
        {
            Accounts = accounts;
        }
    }
}
