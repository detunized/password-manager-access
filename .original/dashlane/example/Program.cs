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

            // 1. On a machine that has a Dashlane client installed we could rummage through
            // the settings database and find the UKI that is used by the client. This way
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

            // 2. Alternatively we could try to generate a new UKI and register it with the
            // server. The process is interactive and is made up of two steps. Step one
            // initiates the process and triggers an email to be sent to the user and the
            // registered email address with a security token.
            // In step 2 the token along with the machine name and the new UKI is registered
            // with the server. After these two steps the new UKI could be used to authenticate
            // with the Dashlane server and fetch the vault.
            if (uki == "")
            {
                try
                {
                    // Request a security token to be sent to the user's email address.
                    Remote.RegisterUkiStep1(username);

                    // Ask the user to enter the token.
                    Console.Write("Enter the token sent by email: ");
                    Console.Out.Flush();
                    var token = Console.ReadLine().Trim();

                    // Generate a new UKI.
                    var newUki = Uki.Generate();

                    // Register all that with the server.
                    Remote.RegisterUkiStep2(username, "dashlane-sharp", newUki, token);

                    // Great success!
                    uki = newUki;
                }
                catch (RegisterException e)
                {
                    Console.WriteLine("Register failed: {0} ({1})", e.Message, e.Reason);
                }
            }

            // We still don't have a valid UKI. Cannot proceed any further.
            if (uki == "")
                return;

            // Now, when we have a registered UKI we can try to open the vault.
            try
            {
                // Fetch and parse first.
                var vault = Vault.Open(username, password, uki);

                // And then dump the accounts.
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
            catch (FetchException e)
            {
                Console.WriteLine("Vault open failed: {0} ({1})", e.Message, e.Reason);
            }
        }
    }
}
