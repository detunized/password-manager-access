// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.LastPass
{
    public class Vault
    {
        public readonly Account[] Accounts;

        public static Vault Open(string username, string password, ClientInfo clientInfo, Ui ui)
        {
            using var transport = new RestTransport();
            return new Vault(Client.OpenVault(username, password, clientInfo, ui, transport));
        }

        public static string GenerateRandomClientId()
        {
            return Crypto.RandomHex(32);
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
