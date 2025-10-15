// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Threading.Tasks;
using PasswordManagerAccess.Common;

namespace OnePasswordAvalonia;

// This is a simple in-memory storage for demonstration purposes
internal class AsyncPlainStorage : IAsyncSecureStorage
{
    private readonly Dictionary<string, string?> _storage = new();

    public Task<string?> LoadString(string name)
    {
        _storage.TryGetValue(name, out var value);
        return Task.FromResult(value);
    }

    public Task StoreString(string name, string? value)
    {
        if (value == null)
            _storage.Remove(name);
        else
            _storage[name] = value;

        return Task.CompletedTask;
    }
}
