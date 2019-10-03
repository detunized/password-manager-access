// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using PasswordManagerAccess.Dashlane;
using PasswordManagerAccess.Example.Common;

namespace Example
{
    class TextUi: Ui
    {
        public override Passcode ProvideGoogleAuthPasscode(int attempt)
        {
            if (attempt > 0)
                Bad("Google Authenticator code is invalid, try again");

            return GetPasscode($"Please enter Google Authenticator code {ToCancel}");
        }

        public override EmailToken ProvideEmailToken()
        {
            var answer = GetAnswer($"Please check your email and enter the security token {ToCancel} " +
                                   "or 'r' to resend the token");
            switch (answer)
            {
            case "":
                return EmailToken.Cancel;
            case "r":
            case "R":
                return EmailToken.Resend;
            default:
                return new EmailToken(answer);
            }
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

            // The UKI is optional.
            var uki = config.ContainsKey("uki") ? config["uki"] : "";

            // It seems we don't have an UKI. We need one to authenticate with the server. An UKI is
            // a device id that is registered with the Dashlane server. There are two ways to obtain
            // one.

            // On a machine that has a Dashlane client installed we could rummage through the
            // settings database and find the UKI that is used by the client. This way we can
            // pretend to be that client and silently authenticate with the server.
            if (uki == "")
            {
                try
                {
                    Console.WriteLine("No UKI is specified. Looking for the local Dashlane");
                    Console.WriteLine($"settings database (profile name: {username})");

                    uki = Import.ImportUki(username, password);

                    Console.WriteLine($"Found an UKI in the local database: {uki}");
                }
                catch (ImportException e)
                {
                    Console.WriteLine("Could not import the UKI from the local Dashlane setting)");
                    Console.WriteLine($"Error: {e.Message} ({e.Reason})");
                }
            }

            // Alternatively we could try to generate a new UKI and register it with the server. The
            // process is interactive. The server will send an email with a security token that the
            // user must provide via the Ui interface. This UKI should be used on subsequent runs.
            if (uki == "")
            {
                uki = Uki.Generate();
                Console.WriteLine($"Generated a new UKI: {uki}");
            }

            try
            {
                // Fetch and parse first.
                Console.WriteLine("Fetching and parsing the remote vault");
                var vault = Vault.Open(username, password, uki, new TextUi());

                // And then dump the accounts.
                Console.WriteLine("The vault has {0} account(s) in it:", vault.Accounts.Length);
                for (var i = 0; i < vault.Accounts.Length; i++)
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
            catch (PasswordManagerAccess.Common.BaseException e)
            {
                Util.PrintException(e);
            }
            catch (ParseException e)
            {
                Console.WriteLine("Could not parse the vault");
                Console.WriteLine("Error: {0} ({1})", e.Message, e.Reason);
            }
        }
    }
}
