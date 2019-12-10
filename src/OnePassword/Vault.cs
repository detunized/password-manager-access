// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace OnePassword
{
    public class Vault
    {
        public readonly string Id;
        public readonly string Name;
        public readonly string Description;
        public readonly Account[] Accounts;

        internal Vault(string id, string name, string description, Account[] accounts)
        {
            Id = id;
            Name = name;
            Description = description;
            Accounts = accounts;
        }
    }
}
