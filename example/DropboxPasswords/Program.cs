// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Example.Common;
using PasswordManagerAccess.DropboxPasswords;

namespace PasswordManagerAccess.Example.DropboxPasswords
{
    public static class Program
    {
        static void Main(string[] args)
        {
            var config = Util.ReadConfig();

            try
            {
                var words = config["recovery-words"].Split(' ');
                if (words.Length != 12)
                {
                    Console.WriteLine("Exactly 12 words separated by a single space should be provided.\n" +
                                      "See config.yaml.example for reference.");
                    return;
                }

                var accounts = Vault.Open(config["oauth-token"], words).Accounts;
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
                                      account.Folder);

                }
            }
            catch (BaseException e)
            {
                Util.PrintException(e);
            }
        }
    }
}
