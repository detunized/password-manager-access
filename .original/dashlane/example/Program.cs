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
        // TODO: Add some comments and some error handling!
        static void Main(string[] args)
        {
            // Read Dashlane credentials from a file
            // The file should contain 3 lines: username, password and uki.
            // The uki is optional.
            // See credentials.txt.example for an example.
            var credentials = File.ReadAllLines("../../credentials.txt");
            var username = credentials[0];
            var password = credentials[1];

            var uki = credentials.ElementAtOrDefault(2);
            if (string.IsNullOrWhiteSpace(uki))
                uki = "";

            if (uki == "")
                uki = Import.ImportUki(username, password);

            var vault = Vault.Open(username, password, uki);

            for (var i = 0; i < vault.Accounts.Length; i++)
            {
                var account = vault.Accounts[i];
                Console.WriteLine(
                    "{0}: {1} {2} {3} {4} {5} {6}",
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
