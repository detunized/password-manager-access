// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System.Threading;
using System.Threading.Tasks;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.LastPass.Ui;

namespace PasswordManagerAccess.LastPass
{
    public class Vault
    {
        public readonly Account[] Accounts;

        public static async Task<Vault> Open(
            string username,
            string password,
            ClientInfo clientInfo,
            IAsyncUi ui,
            ParserOptions options,
            ISecureLogger? logger,
            CancellationToken cancellationToken
        )
        {
            using var transport = new RestTransport();
            return new Vault(
                await Client.OpenVault(username, password, clientInfo, ui, transport, options, logger, cancellationToken).ConfigureAwait(false)
            );
        }

        // This method should be used to check if the user account is an SSO account.
        // In case of the SSO account the password in the Open method should be left blank.
        public static Task<bool> IsSsoAccount(string username, CancellationToken cancellationToken)
        {
            using var transport = new RestTransport();
            return Client.IsSsoAccount(username, transport, cancellationToken);
        }

        public static string GenerateRandomClientId() => Crypto.RandomHex(32);

        //
        // Private
        //

        private Vault(Account[] accounts)
        {
            Accounts = accounts;
        }
    }
}
