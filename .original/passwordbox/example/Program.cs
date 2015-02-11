// Copyright (C) 2015 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.IO;
using PasswordBox;

namespace Example
{
    class Program
    {
        static void Main(string[] args)
        {
            // Read PasswordBox credentials from a file
            // The file should contain 2 lines: username and password.
            // See credentials.txt.example for an example.
            var credentials = File.ReadAllLines("../../credentials.txt");
            var username = credentials[0];
            var password = credentials[1];

            // Log in, fetch data, parse it, log out.
            var vault = Vault.Create(username, password);

            // Print all the accounts
            for (var i = 0; i < vault.Accounts.Length; ++i)
            {
                var account = vault.Accounts[i];
                Console.WriteLine("{0}: {1} {2} {3} {4} {5} {6}",
                                  i + 1,
                                  account.Id,
                                  account.Name,
                                  account.Username,
                                  account.Password,
                                  account.Url,
                                  account.Notes);
            }
        }
    }
}
