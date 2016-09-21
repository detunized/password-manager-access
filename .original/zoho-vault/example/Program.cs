// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.IO;
using ZohoVault;

namespace Example
{
    class Program
    {
        static void Main()
        {
            // Read ZohoVault credentials from a file
            // The file should contain 3 lines: username, password and passphrase
            // See credentials.txt.example for an example.
            var credentials = File.ReadAllLines("../../credentials.txt");
            var username = credentials[0];
            var password = credentials[1];
            var passphrase = credentials[2];

            // Log in, fetch data, parse it, log out.
            var vault = Vault.Open(username, password, passphrase);

            // Print all the accounts
            for (var i = 0; i < vault.Accounts.Length; i += 1)
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
