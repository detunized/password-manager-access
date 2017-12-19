// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.IO;
using RoboForm;

namespace Example
{
    class Program
    {
        private static void Main(string[] args)
        {
            // Read RoboForm credentials from a file
            // The file should contain 2 lines: username and password
            // See credentials.txt.example for an example.
            var credentials = File.ReadAllLines("../../credentials.txt");
            var username = credentials[0];
            var password = credentials[1];

            try
            {
                var vault = Vault.Open(username, password);
                for (var i = 0; i < vault.Accounts.Length; ++i)
                {
                    var a = vault.Accounts[i];
                    Console.WriteLine("{0}: {1} {2} {3}", i + 1, a.Name, a.Path, a.Url);
                    foreach (var field in a.Fields)
                        Console.WriteLine("  - {0}: {1}", field.Name, field.Value);
                }
            }
            catch (BaseException e)
            {
                Console.WriteLine("Error: {0}", e);
            }
        }
    }
}
