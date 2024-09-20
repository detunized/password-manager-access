// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System;
using System.Threading;
using System.Threading.Tasks;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.ProtonPass
{
    public class Vault
    {
        public string Id { get; internal set; } = "";
        public string Name { get; internal set; } = "";
        public string Description { get; internal set; } = "";
        public Account[] Accounts { get; internal set; } = Array.Empty<Account>();

        // TODO: Consider removing the = default on the cancellation token
        public static async Task<Vault[]> OpenAll(
            string username,
            string password,
            IAsyncUi ui,
            IAsyncSecureStorage storage,
            CancellationToken cancellationToken = default
        )
        {
            return await OpenAll(username, password, ui, storage, new RestAsync.Config(), cancellationToken).ConfigureAwait(false);
        }

        //
        // Internal
        //

        internal static async Task<Vault[]> OpenAll(
            string username,
            string password,
            IAsyncUi ui,
            IAsyncSecureStorage storage,
            RestAsync.Config config,
            CancellationToken cancellationToken
        )
        {
            return await Client.OpenAll(username, password, ui, storage, config, cancellationToken).ConfigureAwait(false);
        }
    }
}
