// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System.Threading;
using System.Threading.Tasks;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.ProtonPass
{
    public class Vault
    {
        // TODO: Consider removing the = default on the cancellation token
        public static async Task<Vault> Open(string username,
                                             string password,
                                             IAsyncUi ui,
                                             CancellationToken cancellationToken = default)
        {
            return await Open(username, password, ui, new RestAsync.Config(), cancellationToken);
        }

        //
        // Internal
        //

        internal static async Task<Vault> Open(string username,
                                               string password,
                                               IAsyncUi ui,
                                               RestAsync.Config config,
                                               CancellationToken cancellationToken)
        {
            await Client.Open(username, password, ui, config, cancellationToken);
            return new Vault();
        }
    }
}
