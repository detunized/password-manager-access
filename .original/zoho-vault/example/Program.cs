// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using ZohoVault;

namespace Example
{
    class Program
    {
        static void Main(string[] args)
        {
            // TODO: Read credentials from a file
            var vault = Vault.Open("username", "password", "passphrase");

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
