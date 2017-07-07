// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.IO;
using OnePassword;

namespace Example
{
    class Program
    {
        static void Main(string[] args)
        {
            // Read 1Password credentials from a file
            // The file should contain 4 lines: username, password, account key and the client UUID
            // See credentials.txt.example for an example.
            var credentials = File.ReadAllLines("../../credentials.txt");
            var username = credentials[0];
            var password = credentials[1];
            var accountKey = credentials[2];
            var uuid = credentials[3];

            var vaults = Client.OpenAllVaults(username, password, accountKey, uuid);

            foreach (var vault in vaults)
            {
                Console.WriteLine("{0} {1} {2}", vault.Id, vault.Name, vault.Description);
                for (int i = 0; i < vault.Accounts.Length; ++i)
                {
                    var account = vault.Accounts[i];
                    Console.WriteLine("  - {0}: {1} {2} {3} {4} {5} {6}",
                                      i + 1,
                                      account.Id,
                                      account.Name,
                                      account.Username,
                                      account.Password,
                                      account.Url,
                                      account.Note);
                }
            }
        }
    }
}
