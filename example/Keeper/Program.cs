// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Keeper;
using PasswordManagerAccess.Example.Common;

namespace PasswordManagerAccess.Example.Keeper
{
    class TextUi: Ui
    {
        public override void Close()
        {
        }

        public override Passcode ProvideGoogleAuthPasscode()
        {
            return new Passcode("123456", false);
        }
    }

    static class Program
    {
        public static void Main()
        {
            var config = Util.ReadConfig();
            var accounts = OpenVault(config["username"], config["password"]);
            for (var i = 0; i < accounts.Length; i++)
            {
                var a = accounts[i];
                Console.WriteLine($"====[ {i + 1} ]============");
                Console.WriteLine($"        id: {a.Id}");
                Console.WriteLine($"      name: {a.Name}");
                Console.WriteLine($"  username: {a.Username}");
                Console.WriteLine($"  password: {a.Password}");
                Console.WriteLine($"       url: {a.Url}");
                Console.WriteLine($"      note: {a.Note}");
                Console.WriteLine($"    folder: {a.Folder}");
            }
        }

        private static Account[] OpenVault(string username, string password)
        {
            try
            {
                return Vault.Open(username, password, new TextUi());
            }
            catch (BaseException e)
            {
                Util.PrintException(e);
                Environment.Exit(1);

                // Exit doesn't return, just to mute the warning
                return null;
            }
        }
    }
}
