// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Dashlane;
using PasswordManagerAccess.Example.Common;

namespace PasswordManagerAccess.Example.Dashlane
{
    class TextUi: Ui
    {
        public override Passcode ProvideGoogleAuthPasscode(int attempt)
        {
            if (attempt > 0)
                Bad("Google Authenticator code is invalid, try again");

            return GetPasscode($"Please enter Google Authenticator code {ToCancel}");
        }

        public override Passcode ProvideEmailPasscode(int attempt)
        {
            if (attempt > 0)
                Bad("Email security token is invalid, try again");

            var passcode = GetPasscode($"Please check your email and enter the security token {ToCancel} " +
                                       "or 'r' to resend the token");

            switch (passcode.Code)
            {
            case "r":
            case "R":
                return Passcode.Resend;
            default:
                return passcode;
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

            // The device ID is optional.
            var deviceId = config.ContainsKey("device-id") ? config["device-id"] : "";

            // It seems we don't have a device ID. We need one to authenticate with the server. A
            // device ID must be registered with the Dashlane server. There are two ways to obtain
            // one.

            // On a machine that has a Dashlane client installed we could rummage through the
            // settings database and find the device ID that is used by the client. This way we can
            // pretend to be that client and silently authenticate with the server.
            if (deviceId == "")
            {
                try
                {
                    Console.WriteLine("No device ID is specified. Looking for the local Dashlane");
                    Console.WriteLine($"settings database (profile name: {username})");

                    deviceId = Import.ImportLocalDeviceId(username, password);

                    Console.WriteLine($"The device ID is found in the local database: {deviceId}");
                }
                catch (BaseException e)
                {
                    Console.WriteLine("Could not import the device ID from the local Dashlane setting)");
                    Util.PrintException(e);
                }
            }

            // Alternatively, we could try to generate a new device ID and register it with the
            // server. The process is interactive. The server will send an email with a security
            // token that the user must provide via the Ui interface. This device ID should be used
            // on the subsequent runs.
            if (deviceId == "")
            {
                deviceId = Vault.GenerateRandomDeviceId();
                Console.WriteLine($"Generated a new device ID: {deviceId}");
                Console.WriteLine("Please store it and use it on the subsequent runs");
            }

            try
            {
                // Fetch and parse first.
                Console.WriteLine("Fetching and parsing the remote vault");
                var vault = Vault.Open(username, password, new TextUi(), new PlainStorage());

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
            catch (BaseException e)
            {
                Console.WriteLine("Could not open the remote vault");
                Util.PrintException(e);
            }
        }
    }
}
