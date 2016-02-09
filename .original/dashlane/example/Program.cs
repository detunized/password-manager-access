// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.IO;
using System.Linq;
using Dashlane;

namespace Example
{
    class Program
    {
        static void Main(string[] args)
        {
            // Read Dashlane credentials from a file
            // The file should contain 3 lines: username, password and UKI (optional).
            // See credentials.txt.example for an example.
            var credentials = File.ReadAllLines("../../credentials.txt");
            var username = credentials[0];
            var password = credentials[1];

            // The UKI is optional.
            var uki = credentials.ElementAtOrDefault(2);
            if (string.IsNullOrWhiteSpace(uki))
                uki = "";

            // It seems we don't have an UKI. We need one to authenticate with the server.
            // An UKI is a device id that is registered with the Dashlane server. There are
            // two ways to obtain one.

            // 1. On a machine that has a Dashlane client installed we can rummage through
            // the settings database and find an UKI that is used by the client. This way
            // we can pretend to be that client and silently authenticate with the server.
            if (uki == "")
            {
                try
                {
                    uki = Import.ImportUki(username, password);
                }
                catch (ImportException e)
                {
                    Console.WriteLine("Import failed: {0} ({1})", e.Message, e.Reason);
                }
            }

            // 2. ...
            if (uki == "")
            {
                // TODO: Register an UKI!
            }

            // Now, when we have a registered UKI we can try to fetch and open the vault.
            Vault vault;
            try
            {
                vault = Vault.Open(username, password, uki);
            }
            catch (FetchException e)
            {
                Console.WriteLine("Vault fetch failed: {0} ({1})", e.Message, e.Reason);
                return;
            }

            // Dump the vault
            for (var i = 0; i < vault.Accounts.Length; i++)
            {
                var account = vault.Accounts[i];
                Console.WriteLine(
                    "{0}: {1} {2} {3} {4} {5}",
                    i + 1,
                    account.Name,
                    account.Username,
                    account.Password,
                    account.Url,
                    account.Note);
            }
        }
    }
}
