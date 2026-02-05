// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Example.Common;
using PasswordManagerAccess.NordPass;

namespace PasswordManagerAccess.Example.NordPass;

static class Program
{
    static void Main(string[] args)
    {
        var config = Util.ReadConfig();

        try
        {
            var vault = Vault.Open(config["username"], config["password"]);

            for (var i = 0; i < vault.Accounts.Length; ++i)
            {
                var a = vault.Accounts[i];
                Console.WriteLine(
                    "{0}:\n" +
                    "          id: {1}\n" +
                    "        name: {2}\n" +
                    "    username: {3}\n" +
                    "    password: {4}\n" +
                    "         url: {5}\n" +
                    "        note: {6}\n",
                    i + 1,
                    a.Id,
                    a.Name,
                    a.Username,
                    a.Password,
                    a.Url,
                    a.Note
                );
            }
        }
        catch (BaseException e)
        {
            Util.PrintException(e);
        }
    }
}
