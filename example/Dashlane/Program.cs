// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Dashlane;
using PasswordManagerAccess.Example.Common;

namespace PasswordManagerAccess.Example.Dashlane
{
    class TextUi(string totpSecret) : Ui
    {
        public override Passcode ProvideGoogleAuthPasscode(int attempt)
        {
            if (attempt > 0)
                Bad("Google Authenticator code is invalid, try again");

            if (!string.IsNullOrEmpty(totpSecret))
            {
                var totp = Util.CalculateGoogleAuthTotp(totpSecret);
                Console.WriteLine($"Auto-generated TOTP: {totp}");
                return new Passcode(totp, false);
            }

            return GetPasscode($"Please enter Google Authenticator code {ToCancel}");
        }

        public override Passcode ProvideEmailPasscode(int attempt)
        {
            if (attempt > 0)
                Bad("Email security token is invalid, try again");

            var passcode = GetPasscode($"Please check your email and enter the security token {ToCancel} " + "or 'r' to resend the token");

            switch (passcode.Code)
            {
                case "r":
                case "R":
                    return Passcode.Resend;
                default:
                    return passcode;
            }
        }

        public override bool OpenInBrowser(string url, int attempt)
        {
            Console.WriteLine("Please open the following URL in your browser to trigger the email token:");
            Console.WriteLine(url);
            Console.WriteLine("Press ENTER when you're done or type 'c' to cancel");

            return Console.ReadLine()?.Trim().ToLower() != "c";
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
        static void Main(string[] args)
        {
            var config = Util.ReadConfig();

            var username = config["username"];
            var password = config["password"];
            config.TryGetValue("google-auth-totp-secret", out var totpSecret);

            try
            {
                // Fetch and parse first.
                Console.WriteLine("Fetching and parsing the remote vault");
                var vault = Vault.Open(username, password, new TextUi(totpSecret), new PlainStorage());

                // And then dump the accounts.
                Console.WriteLine("The vault has {0} account(s) in it:", vault.Accounts.Length);
                for (var i = 0; i < vault.Accounts.Length; i++)
                {
                    var account = vault.Accounts[i];
                    Console.WriteLine("{0}: {1} {2} {3} {4} {5}", i + 1, account.Name, account.Username, account.Password, account.Url, account.Note);
                }
            }
            catch (BaseException e)
            {
                Console.WriteLine("Could not open the remote vault");
                Util.PrintException(e);
            }
        }
    }
}
