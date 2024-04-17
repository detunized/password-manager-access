// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System.Threading.Tasks;

namespace PasswordManagerAccess.Common
{
    public interface IAsyncSecureStorage
    {
        // Returns null if no value exists
        Task<string?> LoadString(string name);

        // Pass null to delete the value
        Task StoreString(string name, string? value);
    }
}
