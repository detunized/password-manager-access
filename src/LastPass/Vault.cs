// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;
using PasswordManagerAccess.LastPass.Ui;

namespace PasswordManagerAccess.LastPass
{
    public class Vault
    {
        public readonly Account[] Accounts;

        public static Vault Open(string username, string password, ClientInfo clientInfo, IUi ui)
        {
            return Open(username, password, clientInfo, ui, ParserOptions.Default);
        }

        public static Vault Open(string username, string password, ClientInfo clientInfo, IUi ui, ParserOptions options)
        {
            using var transport = new RestTransport();
            return new Vault(Client.OpenVault(username, password, clientInfo, ui, transport, options));
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
