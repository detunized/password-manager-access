// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using PasswordManagerAccess.Example.Common;
using PasswordManagerAccess.RoboForm;

namespace PasswordManagerAccess.Example.RoboForm
{
    public static class Program
    {
        private class TextUi: Ui
        {
            private const string ToCancel = "or just press ENTER to cancel";

            public override SecondFactorPassword ProvideSecondFactorPassword(string kind)
            {
                return GetPasscode($"Please enter {kind} MFA code {ToCancel}");
            }

            private static SecondFactorPassword GetPasscode(string prompt)
            {
                var passcode = GetAnswer(prompt);
                if (string.IsNullOrWhiteSpace(passcode))
                    return null;

                return new SecondFactorPassword(passcode, GetRememberMe());
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
        }

        private class ConsoleLogger : Logger
        {
            public override void Log(DateTime timestamp, string text)
            {
                Console.WriteLine("{0}: {1}", timestamp, text);
            }
        }

        public static void Main(string[] args)
        {
            var config = Util.ReadConfig();

            try
            {
                var vault = Vault.Open(config["username"],
                                       config["password"],
                                       config["device-id"],
                                       new TextUi(),
                                       new ConsoleLogger());

                for (var i = 0; i < vault.Accounts.Length; ++i)
                {
                    var a = vault.Accounts[i];

                    Console.WriteLine("{0}: {1} {2} {3}", i + 1, a.Name, a.Path, a.Url);

                    foreach (var field in a.Fields)
                        Console.WriteLine("  - {0}: {1}", field.Name, field.Value);

                    if (a.GuessedUsername != null)
                        Console.WriteLine("  * guessed username: {0}", a.GuessedUsername);

                    if (a.GuessedPassword != null)
                        Console.WriteLine("  * guessed password: {0}", a.GuessedPassword);
                }
            }
            catch (BaseException e)
            {
                Console.WriteLine("Error: {0}", e);
            }
        }
    }
}
