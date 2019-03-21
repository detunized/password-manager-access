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
        public override Passcode ProvideGoogleAuthPasscode(int attempt)
        {
            if (attempt > 0)
                Bad("Google Authenticator code is invalid, try again");

            return GetPasscode($"Please enter Google Authenticator code {ToCancel}");
        }

        public override Passcode ProvideSmsPasscode(int attempt)
        {
            if (attempt > 0)
                Bad("SMS code is invalid, try again");

            return GetPasscode($"Please enter SMS code {ToCancel}");
        }

        //
        // Private
        //

        private static Passcode GetPasscode(string prompt)
        {
            var passcode = GetAnswer(prompt);
            return passcode == "" ? Passcode.Cancel : new Passcode(passcode, GetRememberMe());
        }

        private static string GetAnswer(string prompt)
        {
            Console.WriteLine(prompt);
            Console.Write("> ");
            var input = Console.ReadLine();

            return input == null ? "" : input.Trim();
        }

        private static bool GetRememberMe()
        {
            var remember = GetAnswer("Remember this device?").ToLower();
            return remember == "y" || remember == "yes";
        }

        private static void Bad(string text)
        {
            WriteLine(ConsoleColor.Red, text);
        }

        private static void WriteLine(ConsoleColor color, string text)
        {
            Console.ForegroundColor = color;
            Console.WriteLine(text);
            Console.ResetColor();
        }

        private const string ToCancel = "or just press ENTER to cancel";
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
                return Vault.Open(username, password, new TextUi(), new PlainStorage());
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
