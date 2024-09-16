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

        public static async Task<Vault> Open(string username,
                                             string password,
                                             ClientInfo clientInfo,
                                             IUi ui,
                                             ParserOptions options,
                                             CancellationToken cancellationToken)
        {
            return await Open(username, password, clientInfo, ui, options, new RestAsync.Config(), cancellationToken).ConfigureAwait(false);
        }

        public static string GenerateRandomClientId()
        {
            return Crypto.RandomHex(32);
        }

        //
        // Internal
        //

        internal static async Task<Vault> Open(string username,
                                               string password,
                                               ClientInfo clientInfo,
                                               IUi ui,
                                               ParserOptions options,
                                               RestAsync.Config restConfig,
                                               CancellationToken cancellationToken)
        {
            var accounts = await Client.OpenVault(username, password, clientInfo, ui, options, restConfig, cancellationToken).ConfigureAwait(false);
            return new Vault(accounts);
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
