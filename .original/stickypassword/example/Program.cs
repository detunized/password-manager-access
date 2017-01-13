// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.IO;
using StickyPassword;

namespace Example
{
    class Program
    {
        static void Main(string[] args)
        {
            // Read StickyPassword credentials from a file
            // The file should contain 2 lines: username and password
            // See credentials.txt.example for an example.
            var credentials = File.ReadAllLines("../../credentials.txt");
            var username = credentials[0];
            var password = credentials[1];

            var vault = Vault.Open(username, password);
            for (var i = 0; i < vault.Accounts.Length; ++i)
            {
                var a = vault.Accounts[i];
                Console.WriteLine("{0}: {1} {2} {3} {4}",
                                  i + 1,
                                  a.Id,
                                  a.Name,
                                  a.Url,
                                  a.Notes);

                for (var j = 0; j < a.Credentials.Length; ++j)
                {
                    var c = a.Credentials[j];
                    Console.WriteLine("  - {0}: {1}:{2} ({3})",
                                      j + 1,
                                      c.Username,
                                      c.Password,
                                      c.Description);
                }
            }
        }
    }
}
