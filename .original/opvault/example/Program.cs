// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using OPVault;

namespace Example
{
    class Program
    {
        static void Main(string[] args)
        {
            // Use one from the tests by default
            var path = "../../../test/test.opvault";
            var password = "password";

            if (args.Length == 2)
            {
                path = args[0];
                password = args[1];
            }

            var accounts = Vault.Open(path, password);
            for (var i = 0; i < accounts.Length; ++i)
            {
                var account = accounts[i];
                Console.WriteLine("  - {0}: {1} {2} {3} {4} {5} {6} {7}",
                                  i + 1,
                                  account.Id,
                                  account.Name,
                                  account.Username,
                                  account.Password,
                                  account.Url,
                                  account.Note,
                                  account.Folder.Name);

            }
        }
    }
}
