// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Example.Common;
using PasswordManagerAccess.Kaspersky;

namespace PasswordManagerAccess.Example.Kaspersky
{
    public static class Program
    {
        public static void Main(string[] args)
        {
            var config = Util.ReadConfig();

            try
            {
                var vault = Vault.Open(config["username"], config["account-password"], config["vault-password"]);
                for (var i = 0; i < vault.Accounts.Length; ++i)
                {
                    var a = vault.Accounts[i];
                    Console.WriteLine("{0}: {1} {2} {3} {4} {5}", i + 1, a.Id, a.Name, a.Url, a.Notes, a.Folder);

                    for (var j = 0; j < a.Credentials.Length; ++j)
                    {
                        var c = a.Credentials[j];
                        Console.WriteLine("  - {0}: {1} {2} {3}:{4} ({5})", j + 1, c.Id, c.Name, c.Username, c.Password, c.Notes);
                    }
                }
            }
            catch (BaseException e)
            {
                Util.PrintException(e);
            }
        }
    }
}
