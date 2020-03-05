// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using PasswordManagerAccess.Example.Common;
using PasswordManagerAccess.StickyPassword;

namespace PasswordManagerAccess.Example.StickyPassword
{
    public static class Program
    {
        static void Main(string[] args)
        {
            var config = Util.ReadConfig();

            var vault = Vault.Open(config["username"], config["password"]);
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
