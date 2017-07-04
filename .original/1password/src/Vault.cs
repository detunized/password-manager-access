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

        // Public entry point to the library.
        // We try to mimic the remote structure, that's why there's an array of vaults.
        // We open all the ones we can.
        public static Vault[] OpenAll(string username,
                                      string password,
                                      string accountKey,
                                      string uuid,
                                      IHttpClient http)
        {
            return new Client(http).OpenAllVaults(new ClientInfo(username,
                                                                 password,
                                                                 accountKey,
                                                                 uuid));
        }

        internal Vault(string id, string name, string description, Account[] accounts)
        {
            Id = id;
            Name = name;
            Description = description;
            Accounts = accounts;
        }
    }
}
