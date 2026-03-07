// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System.Threading;
using System.Threading.Tasks;

namespace PasswordManagerAccess.Common
{
    // Secure storage that is safe to use to disable the "remember me" feature.
    // Simply pass `new NullStorage()` to `Vault.Open` of any of the password managers
    // when the "remember me" feature is not needed.
    public class NullStorage : ISecureStorage, IAsyncSecureStorage
    {
        //
        // ISecureStorage
        //

        public string? LoadString(string name) => null;

        public void StoreString(string name, string? value) { }

        //
        // IAsyncSecureStorage
        //

        public Task<string?> LoadString(string name, CancellationToken cancellationToken) => Task.FromResult<string?>(null);

        public Task StoreString(string name, string? value, CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
