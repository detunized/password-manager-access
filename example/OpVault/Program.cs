// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using PasswordManagerAccess.Example.Common;
using PasswordManagerAccess.OpVault;

namespace PasswordManagerAccess.Example.OpVault
{
    public static class Program
    {
        static void Main(string[] args)
        {
            var config = Util.ReadConfig();

            // Use one from the tests by default
            if (!config.ContainsKey("path") || !config.ContainsKey("password"))
            {
                config["path"] = "../../../../../test/OpVault/Fixtures/test.opvault";
                config["password"] = "password";
            }

            var accounts = Vault.Open(config["path"], config["password"]);
            for (var i = 0; i < accounts.Length; ++i)
            {
                var account = accounts[i];
                Console.WriteLine(
                    "  - {0}: {1} {2} {3} {4} {5} {6} {7}",
                    i + 1,
                    account.Id,
                    account.Name,
                    account.Username,
                    account.Password,
                    account.Url,
                    account.Note,
                    account.Folder.Name
                );
            }
        }
    }
}
