// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Threading;
using System.Threading.Tasks;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.LastPass.Ui;

namespace PasswordManagerAccess.LastPass
{
    public class Vault
    {
        public readonly Account[] Accounts;

        public static async Task<Vault> Open(string username, string password, ClientInfo clientInfo, IUi ui, CancellationToken cancellationToken)
        {
            return await Open(username, password, clientInfo, ui, ParserOptions.Default, cancellationToken).ConfigureAwait(false);
        }

        public static async Task<Vault> Open(
            string username,
            string password,
            ClientInfo clientInfo,
            IUi ui,
            ParserOptions options,
            CancellationToken cancellationToken
        )
        {
            using var transport = new RestTransport();
            return new Vault(await Client.OpenVault(username, password, clientInfo, ui, transport, options, cancellationToken).ConfigureAwait(false));
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
