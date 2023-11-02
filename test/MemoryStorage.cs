// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Test
{
    public class MemoryStorage: ISecureStorage
    {
        public Dictionary<string, string> Values { get; } = new Dictionary<string, string>();
        public Func<string, string> OnMissingValue { get; }

        public MemoryStorage(Dictionary<string, string> values = null, Func<string, string> onMissingValue = null)
        {
            foreach (var kv in values ?? new Dictionary<string, string>())
                Values[kv.Key] = kv.Value;

            OnMissingValue = onMissingValue ?? (name => "");
        }

        public string LoadString(string name)
        {
            return Values.TryGetValue(name, out var value) ? value : OnMissingValue(name);
        }

        public void StoreString(string name, string value)
        {
            Values[name] = value;
        }
    }
}
