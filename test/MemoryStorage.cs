// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Test
{
    public class MemoryStorage: ISecureStorage, IAsyncSecureStorage
    {
        public Dictionary<string, string> Values { get; } = new();
        public Func<string, string> OnMissingValue { get; }

        public MemoryStorage(Dictionary<string, string> values = null, Func<string, string> onMissingValue = null)
        {
            foreach (var kv in values ?? new Dictionary<string, string>())
                Values[kv.Key] = kv.Value;

            OnMissingValue = onMissingValue ?? (name => "");
        }

        string ISecureStorage.LoadString(string name)
        {
            return Values.TryGetValue(name, out var value) ? value : OnMissingValue(name);
        }

        void ISecureStorage.StoreString(string name, string value)
        {
            if (value == null)
                Values.Remove(name);
            else
                Values[name] = value;
        }

        Task<string> IAsyncSecureStorage.LoadString(string name)
        {
            return Task.FromResult(((ISecureStorage)this).LoadString(name));
        }

        Task IAsyncSecureStorage.StoreString(string name, string value)
        {
            ((ISecureStorage)this).StoreString(name, value);
            return Task.CompletedTask;
        }
    }
}
