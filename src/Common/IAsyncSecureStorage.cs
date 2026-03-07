// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System.Threading;
using System.Threading.Tasks;

namespace PasswordManagerAccess.Common
{
    public interface IAsyncSecureStorage
    {
        // Returns null if no value exists
        Task<string?> LoadString(string name, CancellationToken cancellationToken);

        // Pass null to delete the value
        Task StoreString(string name, string? value, CancellationToken cancellationToken);

        //
        // Internal
        //

        // Convenience method to delete a value
        internal Task DeleteString(string name, CancellationToken cancellationToken) => StoreString(name, null, cancellationToken);
    }
}
