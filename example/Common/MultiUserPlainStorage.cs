// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System.Threading;
using System.Threading.Tasks;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Example.Common;

// Wraps a storage instance and prepends a username to all keys, so that
// multiple users can share the same underlying storage file.
public class MultiUserPlainStorage(IAsyncSecureStorage inner, string username) : IAsyncSecureStorage
{
    public Task<string?> LoadString(string name, CancellationToken cancellationToken) => inner.LoadString($"{username}/{name}", cancellationToken);

    public Task StoreString(string name, string? value, CancellationToken cancellationToken) =>
        inner.StoreString($"{username}/{name}", value, cancellationToken);
}
