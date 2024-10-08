// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using PasswordManagerAccess.Common;
using PasswordManagerAccess.LastPass.Ui;

namespace PasswordManagerAccess.LastPass
{
    public class Vault
    {
        public readonly Account[] Accounts;

        public static Vault Open(string username, string password, ClientInfo clientInfo, IUi ui, ISecureLogger? logger = null) =>
            Open(username, password, clientInfo, ui, ParserOptions.Default, logger);

        public static Vault Open(string username, string password, ClientInfo clientInfo, IUi ui, ParserOptions options, ISecureLogger? logger = null)
        {
            using var transport = new RestTransport();
            return new Vault(Client.OpenVault(username, password, clientInfo, ui, transport, options, logger));
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
